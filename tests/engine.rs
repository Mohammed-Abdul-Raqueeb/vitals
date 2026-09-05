//! Ring buffer, delta arithmetic, and alert engine tests.
//!
//! Time is injected everywhere rather than slept on, so these run in
//! milliseconds and produce identical results every time.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use vitals::delta::diff;
use vitals::procfs::{CpuTimes, MemInfo, NetDev, PidIo, PidStat, StatFile};
use vitals::ring::Ring;
use vitals::rules::{parse_rules, Engine, EventKind, Metric, Op, Target};
use vitals::sample::{ProcSample, Sample};

// ------------------------------------------------------------ ring buffer --

#[test]
fn ring_overwrites_oldest_and_never_grows() {
    let mut r: Ring<u32> = Ring::new(4);
    assert_eq!(r.capacity(), 4);
    for i in 1..=4 {
        assert_eq!(r.push(i), None, "no eviction before full");
    }
    assert!(r.is_full());
    assert_eq!(r.iter_chrono().copied().collect::<Vec<_>>(), vec![1, 2, 3, 4]);

    // Pushing past capacity evicts the oldest and keeps len pinned.
    assert_eq!(r.push(5), Some(1));
    assert_eq!(r.push(6), Some(2));
    assert_eq!(r.len(), 4);
    assert_eq!(r.capacity(), 4, "capacity must never grow");
    assert_eq!(r.iter_chrono().copied().collect::<Vec<_>>(), vec![3, 4, 5, 6]);
    assert_eq!(r.newest(), Some(&6));
    assert_eq!(r.oldest(), Some(&3));
    assert_eq!(r.total_pushed(), 6);
}

#[test]
fn ring_ordering_is_correct_across_many_wraps() {
    let mut r: Ring<usize> = Ring::new(7);
    for i in 0..1000 {
        r.push(i);
    }
    let got: Vec<usize> = r.iter_chrono().copied().collect();
    assert_eq!(got, (993..1000).collect::<Vec<_>>());
    assert_eq!(r.len(), 7);
}

#[test]
fn ring_handles_partial_fill_and_clear() {
    let mut r: Ring<i32> = Ring::new(5);
    r.push(10);
    r.push(20);
    assert_eq!(r.len(), 2);
    assert!(!r.is_full());
    assert_eq!(r.iter_chrono().copied().collect::<Vec<_>>(), vec![10, 20]);
    assert_eq!(r.get(2), None);
    r.clear();
    assert!(r.is_empty());
    assert_eq!(r.newest(), None);
}

#[test]
fn ring_of_zero_capacity_is_clamped_not_silently_useless() {
    let mut r: Ring<u8> = Ring::new(0);
    assert_eq!(r.capacity(), 1);
    r.push(9);
    assert_eq!(r.newest(), Some(&9));
}

// ------------------------------------------------------------ delta tests --

fn mk_proc(pid: i32, starttime: u64, comm: &str, ticks: u64, rss_pages: i64) -> PidStat {
    PidStat {
        pid,
        comm: comm.into(),
        state: 'R',
        ppid: 1,
        utime: ticks,
        stime: 0,
        num_threads: 1,
        starttime,
        vsize: 1000,
        rss_pages,
    }
}

fn mk_sample(at: Instant, cpu_total: CpuTimes, procs: Vec<(PidStat, Option<PidIo>)>) -> Sample {
    let mut map = HashMap::new();
    for (stat, io) in procs {
        map.insert(stat.key(), ProcSample { stat, io, sockets: None });
    }
    Sample {
        at,
        cpu: StatFile { total: cpu_total, per_cpu: vec![], ctxt: 0, procs_running: 1, procs_blocked: 0 },
        mem: MemInfo { total: 1000, free: 100, available: 400, ..Default::default() },
        nets: vec![],
        procs: map,
        vanished: 0,
        io_denied: 0,
        scan_time: Duration::from_micros(500),
    }
}

#[test]
fn per_process_cpu_percent_is_normalised_to_one_core() {
    // USER_HZ is 100 on this machine. A process consuming 100 ticks over one
    // second of wall time used exactly one core: 100%.
    let hz = vitals::units::sys_const().clk_tck;
    let t0 = Instant::now();
    let t1 = t0 + Duration::from_secs(1);

    let a = mk_sample(t0, CpuTimes::default(), vec![(mk_proc(10, 5, "busy", 0, 100), None)]);
    let b = mk_sample(t1, CpuTimes::default(), vec![(mk_proc(10, 5, "busy", hz, 100), None)]);

    let s = diff(&a, &b);
    let p = &s.procs[0];
    assert!((p.cpu_pct - 100.0).abs() < 0.01, "expected ~100%, got {}", p.cpu_pct);
    assert!(!p.is_new);

    // Half the ticks over the same second is half a core.
    let c = mk_sample(t1, CpuTimes::default(), vec![(mk_proc(10, 5, "busy", hz / 2, 100), None)]);
    assert!((diff(&a, &c).procs[0].cpu_pct - 50.0).abs() < 0.01);
}

#[test]
fn recycled_pid_is_treated_as_a_new_process_not_a_huge_delta() {
    // The classic bug: pid 10 exits having used 5000 ticks, a new process gets
    // pid 10 and has used 3. Keying on pid alone yields a negative delta (or,
    // with unsigned math, an 18-quintillion-tick spike). Keying on
    // (pid, starttime) makes it a new process with no rate.
    let t0 = Instant::now();
    let t1 = t0 + Duration::from_secs(1);

    let old = mk_sample(t0, CpuTimes::default(), vec![(mk_proc(10, 111, "old", 5000, 50), None)]);
    let new = mk_sample(t1, CpuTimes::default(), vec![(mk_proc(10, 999, "new", 3, 50), None)]);

    let s = diff(&old, &new);
    assert_eq!(s.procs.len(), 1);
    let p = &s.procs[0];
    assert_eq!(p.comm, "new");
    assert!(p.is_new, "different starttime must mean a different process");
    assert_eq!(p.cpu_pct, 0.0, "no rate can be computed for a first sighting");
}

#[test]
fn counters_going_backwards_saturate_instead_of_underflowing() {
    // 32-bit network counters wrap; a container restart can reset io counters.
    // Saturating gives one wrong-but-harmless sample instead of a garbage spike.
    let t0 = Instant::now();
    let t1 = t0 + Duration::from_secs(1);
    let io_hi = PidIo { rchar: 0, wchar: 0, read_bytes: 1_000_000, write_bytes: 0 };
    let io_lo = PidIo { rchar: 0, wchar: 0, read_bytes: 5, write_bytes: 0 };

    let a = mk_sample(t0, CpuTimes::default(), vec![(mk_proc(1, 1, "x", 500, 1), Some(io_hi))]);
    let b = mk_sample(t1, CpuTimes::default(), vec![(mk_proc(1, 1, "x", 10, 1), Some(io_lo))]);

    let s = diff(&a, &b);
    assert_eq!(s.procs[0].cpu_pct, 0.0, "cpu delta saturates to zero");
    assert_eq!(s.procs[0].read_bps, Some(0.0), "io delta saturates to zero");
}

#[test]
fn system_cpu_uses_the_ratio_within_one_read() {
    let t0 = Instant::now();
    let t1 = t0 + Duration::from_secs(1);
    // busy goes 0 -> 250, total goes 0 -> 1000, so 25%.
    let c0 = CpuTimes { user: 0, idle: 0, ..Default::default() };
    let c1 = CpuTimes { user: 250, idle: 750, ..Default::default() };
    let s = diff(&mk_sample(t0, c0, vec![]), &mk_sample(t1, c1, vec![]));
    assert!((s.system.cpu_pct - 25.0).abs() < 1e-9, "got {}", s.system.cpu_pct);
}

#[test]
fn loopback_is_excluded_from_system_network_rates() {
    // Local traffic appears on both rx and tx of `lo`, so counting it
    // double-counts and makes a chatty local service look like a LAN flood.
    let t0 = Instant::now();
    let t1 = t0 + Duration::from_secs(1);
    let nets = |rx: u64| {
        vec![
            NetDev { name: "lo".into(), rx_bytes: rx * 10, tx_bytes: rx * 10, ..Default::default() },
            NetDev { name: "eth0".into(), rx_bytes: rx, tx_bytes: rx, ..Default::default() },
        ]
    };
    let mut a = mk_sample(t0, CpuTimes::default(), vec![]);
    let mut b = mk_sample(t1, CpuTimes::default(), vec![]);
    a.nets = nets(0);
    b.nets = nets(1000);
    let s = diff(&a, &b);
    assert!((s.system.net_rx_bps - 1000.0).abs() < 1e-9, "lo must not be counted");
}

#[test]
fn processes_are_sorted_by_cpu_descending() {
    let hz = vitals::units::sys_const().clk_tck;
    let t0 = Instant::now();
    let t1 = t0 + Duration::from_secs(1);
    let a = mk_sample(
        t0,
        CpuTimes::default(),
        vec![
            (mk_proc(1, 1, "quiet", 0, 1), None),
            (mk_proc(2, 2, "busy", 0, 1), None),
        ],
    );
    let b = mk_sample(
        t1,
        CpuTimes::default(),
        vec![
            (mk_proc(1, 1, "quiet", hz / 10, 1), None),
            (mk_proc(2, 2, "busy", hz, 1), None),
        ],
    );
    let s = diff(&a, &b);
    assert_eq!(s.procs[0].comm, "busy");
    assert_eq!(s.procs[1].comm, "quiet");
}

// ------------------------------------------------------- rule file parsing --

#[test]
fn rule_file_parses_valid_lines() {
    let text = "
# comments and blank lines are skipped
alert high_cpu   system        cpu_pct  > 80     for 5s  clear 60
alert cpu_hog    process:*     cpu_pct  > 50     for 3s
alert node_leak  process:node  rss      > 500MB  for 30s clear 400MB
alert low_mem    system        mem_pct  > 90     for 10s
";
    let (rules, errs) = parse_rules(text);
    assert!(errs.is_empty(), "unexpected errors: {:?}", errs);
    assert_eq!(rules.len(), 4);

    assert_eq!(rules[0].name, "high_cpu");
    assert_eq!(rules[0].target, Target::System);
    assert_eq!(rules[0].metric, Metric::CpuPct);
    assert_eq!(rules[0].op, Op::Gt);
    assert_eq!(rules[0].threshold, 80.0);
    assert_eq!(rules[0].sustain, Duration::from_secs(5));
    assert_eq!(rules[0].clear, 60.0);

    assert_eq!(rules[1].target, Target::Process("*".into()));
    assert_eq!(rules[2].threshold, 500.0 * 1024.0 * 1024.0, "MB suffix honoured");
    // Absent `clear` means no deadband.
    assert_eq!(rules[3].clear, rules[3].threshold);
}

#[test]
fn rule_file_reports_bad_lines_without_discarding_good_ones() {
    let text = "
alert ok      system     cpu_pct > 50 for 1s
alert bad1    system     nonsense > 50 for 1s
alert bad2    weird:x    cpu_pct  > 50 for 1s
alert bad3    system     cpu_pct  ~ 50 for 1s
alert bad4    system     cpu_pct  > 50 while 1s
alert bad5    process:x  mem_pct  > 50 for 1s
alert bad6    system     cpu_pct  > 50 for 1s clear 90
alert ok2     system     mem_pct  > 90 for 2s
";
    let (rules, errs) = parse_rules(text);
    assert_eq!(rules.len(), 2, "good rules survive");
    assert_eq!(errs.len(), 6, "each bad line reported once");
    // bad5: a system-wide metric cannot be scoped to a process.
    assert!(errs.iter().any(|e| e.reason.contains("system-wide")));
    // bad6: clear above threshold for `>` could never clear -> latched alert.
    assert!(errs.iter().any(|e| e.reason.contains("never clear")));
}

// -------------------------------------------------------- alert behaviour --

fn snap_with_system_cpu(v: f64) -> vitals::delta::Snapshot {
    let t0 = Instant::now();
    let t1 = t0 + Duration::from_secs(1);
    let total = 1000u64;
    let busy = (v / 100.0 * total as f64) as u64;
    let c1 = CpuTimes { user: busy, idle: total - busy, ..Default::default() };
    diff(&mk_sample(t0, CpuTimes::default(), vec![]), &mk_sample(t1, c1, vec![]))
}

#[test]
fn alert_requires_the_condition_to_be_sustained() {
    let (rules, _) = parse_rules("alert hot system cpu_pct > 80 for 5s\n");
    let mut e = Engine::new(rules);
    let t0 = Instant::now();

    // Breaching, but the sustain window has not elapsed.
    assert!(e.evaluate(&snap_with_system_cpu(90.0), t0).is_empty());
    assert!(e.evaluate(&snap_with_system_cpu(90.0), t0 + Duration::from_secs(2)).is_empty());
    assert_eq!(e.active_count(), 0);

    // Past 5s of continuous breach it fires, exactly once.
    let ev = e.evaluate(&snap_with_system_cpu(90.0), t0 + Duration::from_secs(6));
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].kind, EventKind::Fired);
    assert_eq!(ev[0].rule_name, "hot");
    assert_eq!(e.active_count(), 1);

    // Still breaching: no duplicate event.
    assert!(e.evaluate(&snap_with_system_cpu(95.0), t0 + Duration::from_secs(7)).is_empty());
    assert_eq!(e.active_count(), 1);
}

#[test]
fn a_transient_spike_never_fires_and_resets_the_timer() {
    let (rules, _) = parse_rules("alert hot system cpu_pct > 80 for 5s\n");
    let mut e = Engine::new(rules);
    let t0 = Instant::now();

    e.evaluate(&snap_with_system_cpu(90.0), t0); // pending
    e.evaluate(&snap_with_system_cpu(10.0), t0 + Duration::from_secs(1)); // drops out
    // The timer restarts from here, so 6s after t0 is only 5s of... 4s.
    e.evaluate(&snap_with_system_cpu(90.0), t0 + Duration::from_secs(2));
    let ev = e.evaluate(&snap_with_system_cpu(90.0), t0 + Duration::from_secs(6));
    assert!(ev.is_empty(), "sustain window must restart after a dropout");
    // Now it has been continuously breaching since t0+2s.
    let ev = e.evaluate(&snap_with_system_cpu(90.0), t0 + Duration::from_secs(8));
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].kind, EventKind::Fired);
}

#[test]
fn hysteresis_prevents_flapping_around_the_threshold() {
    // Fire above 80, clear only below 60. A value oscillating around 80 must
    // produce exactly one Fired event and no Cleared events.
    let (rules, _) = parse_rules("alert hot system cpu_pct > 80 for 0s clear 60\n");
    let mut e = Engine::new(rules);
    let t0 = Instant::now();

    let mut fired = 0;
    let mut cleared = 0;
    let wobble = [81.0, 79.0, 82.0, 78.0, 85.0, 75.0, 81.0, 79.5];
    for (i, v) in wobble.iter().enumerate() {
        for ev in e.evaluate(&snap_with_system_cpu(*v), t0 + Duration::from_secs(i as u64)) {
            match ev.kind {
                EventKind::Fired => fired += 1,
                _ => cleared += 1,
            }
        }
    }
    assert_eq!(fired, 1, "should fire once, not on every upward crossing");
    assert_eq!(cleared, 0, "must not clear while still above the deadband");

    // Dropping below the clear threshold finally clears it.
    let ev = e.evaluate(&snap_with_system_cpu(55.0), t0 + Duration::from_secs(20));
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].kind, EventKind::Cleared);
    assert_eq!(e.active_count(), 0);
}

#[test]
fn without_hysteresis_the_same_wobble_flaps() {
    // Control for the previous test: no `clear` means the deadband is zero and
    // the alert really does toggle. This proves hysteresis is doing the work.
    let (rules, _) = parse_rules("alert hot system cpu_pct > 80 for 0s\n");
    let mut e = Engine::new(rules);
    let t0 = Instant::now();
    let mut transitions = 0;
    for (i, v) in [81.0, 79.0, 82.0, 78.0, 85.0, 75.0].iter().enumerate() {
        transitions += e
            .evaluate(&snap_with_system_cpu(*v), t0 + Duration::from_secs(i as u64))
            .len();
    }
    assert!(transitions >= 5, "expected flapping without a deadband, got {}", transitions);
}

#[test]
fn a_firing_alert_clears_when_its_process_exits() {
    // Otherwise the alert latches on forever, pointing at a pid that no longer
    // exists — a real failure mode in monitoring tools.
    let (rules, _) = parse_rules("alert hog process:hungry cpu_pct > 50 for 0s\n");
    let mut e = Engine::new(rules);
    let hz = vitals::units::sys_const().clk_tck;
    let t0 = Instant::now();
    let t1 = t0 + Duration::from_secs(1);

    let before = mk_sample(t0, CpuTimes::default(), vec![(mk_proc(42, 7, "hungry", 0, 10), None)]);
    let after = mk_sample(t1, CpuTimes::default(), vec![(mk_proc(42, 7, "hungry", hz, 10), None)]);
    let ev = e.evaluate(&diff(&before, &after), t1);
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].kind, EventKind::Fired);
    assert!(ev[0].subject.contains("pid 42"));
    assert_eq!(e.active_count(), 1);

    // Next tick the process is gone.
    let empty = diff(&after, &mk_sample(t1 + Duration::from_secs(1), CpuTimes::default(), vec![]));
    let ev = e.evaluate(&empty, t1 + Duration::from_secs(1));
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].kind, EventKind::ClearedGone);
    assert_eq!(e.active_count(), 0, "alert must not latch on a dead pid");
}

#[test]
fn brand_new_processes_do_not_trigger_alerts() {
    // A first sighting has no computable rate; alerting on its 0.0 would be
    // meaningless, and alerting on a `<` rule would fire spuriously.
    let (rules, _) = parse_rules("alert idle process:* cpu_pct < 10 for 0s\n");
    let mut e = Engine::new(rules);
    let t0 = Instant::now();
    let t1 = t0 + Duration::from_secs(1);
    let a = mk_sample(t0, CpuTimes::default(), vec![]);
    let b = mk_sample(t1, CpuTimes::default(), vec![(mk_proc(9, 9, "fresh", 0, 1), None)]);
    assert!(e.evaluate(&diff(&a, &b), t1).is_empty());
}
