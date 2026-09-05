//! Turning cumulative counters into rates.
//!
//! Everything in /proc is monotonic-since-boot. A rate exists only between two
//! samples, so this module is where correctness actually lives.
//!
//! Decisions worth defending:
//!
//! * **Elapsed time comes from a monotonic clock**, not wall clock. An NTP step
//!   backwards during a sample interval would otherwise produce a negative
//!   elapsed time and an absurd rate.
//!
//! * **Per-process CPU is normalised against wall time**, not against the delta
//!   of /proc/stat's total. `pct = delta_ticks / (USER_HZ * elapsed_secs) * 100`,
//!   so 100% means "one core fully consumed" and an 8-threaded process on an
//!   8-core box can legitimately read 800%. This is `top`'s convention. The
//!   alternative — dividing by summed /proc/stat ticks — needs both files
//!   sampled at exactly the same instant to be right, and they never are; a
//!   per-process scan takes milliseconds.
//!
//! * **System CPU uses the /proc/stat ratio**, `delta_busy / delta_total`,
//!   because there both numerator and denominator come from the same line of the
//!   same read and are therefore consistent by construction.
//!
//! * **Every subtraction is saturating.** Counters can appear to move backwards:
//!   32-bit network counters wrap, and a process can be replaced by a recycled
//!   PID. Saturating to zero yields a wrong-but-harmless single sample instead of
//!   an underflow panic or a garbage spike of 18 quintillion bytes per second.

use crate::procfs::{MemInfo, ProcKey};
use crate::sample::Sample;
use crate::units::sys_const;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ProcRate {
    pub key: ProcKey,
    pub pid: i32,
    pub ppid: i32,
    pub comm: String,
    pub state: char,
    pub threads: i64,
    /// 100.0 == one core fully consumed.
    pub cpu_pct: f64,
    pub rss_bytes: u64,
    pub vsize_bytes: u64,
    /// Actual block-layer traffic. None when /proc/[pid]/io was unreadable.
    pub read_bps: Option<f64>,
    pub write_bps: Option<f64>,
    /// Syscall-level traffic, which includes page cache, pipes and sockets.
    pub rchar_bps: Option<f64>,
    pub wchar_bps: Option<f64>,
    pub sockets: Option<usize>,
    /// First seen in this interval, so its CPU rate is not yet meaningful.
    pub is_new: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SystemRate {
    pub cpu_pct: f64,
    pub per_cpu_pct: Vec<f64>,
    pub mem: MemInfo,
    pub net_rx_bps: f64,
    pub net_tx_bps: f64,
    pub net_rx_errs: u64,
    pub net_tx_errs: u64,
    pub ctxt_per_sec: f64,
    pub procs_running: u64,
    pub procs_blocked: u64,
    pub proc_count: usize,
    pub vanished: u32,
    pub scan_time: Duration,
    pub interval: Duration,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub system: SystemRate,
    pub procs: Vec<ProcRate>,
}

fn pct(busy_delta: u64, total_delta: u64) -> f64 {
    if total_delta == 0 {
        0.0
    } else {
        (busy_delta as f64 / total_delta as f64 * 100.0).clamp(0.0, 100.0)
    }
}

fn rate(cur: u64, prev: u64, secs: f64) -> f64 {
    if secs <= 0.0 {
        return 0.0;
    }
    cur.saturating_sub(prev) as f64 / secs
}

/// Compute rates between two samples. `prev` must be the earlier one.
pub fn diff(prev: &Sample, cur: &Sample) -> Snapshot {
    let interval = cur.at.saturating_duration_since(prev.at);
    let secs = interval.as_secs_f64();
    let hz = sys_const().clk_tck as f64;

    // ---- system CPU: ratio within a single consistent read ----
    let total_delta = cur.cpu.total.total().saturating_sub(prev.cpu.total.total());
    let busy_delta = cur.cpu.total.busy().saturating_sub(prev.cpu.total.busy());
    let cpu_pct = pct(busy_delta, total_delta);

    let per_cpu_pct = cur
        .cpu
        .per_cpu
        .iter()
        .zip(prev.cpu.per_cpu.iter())
        .map(|(c, p)| pct(c.busy().saturating_sub(p.busy()), c.total().saturating_sub(p.total())))
        .collect();

    // ---- network: sum every interface except loopback ----
    // Loopback is excluded deliberately: local traffic is counted on both rx and
    // tx, so including it double-counts and makes a busy local database look
    // like it is saturating the LAN.
    let sum_net = |s: &Sample| -> (u64, u64, u64, u64) {
        s.nets
            .iter()
            .filter(|n| n.name != "lo")
            .fold((0, 0, 0, 0), |a, n| {
                (a.0 + n.rx_bytes, a.1 + n.tx_bytes, a.2 + n.rx_errs, a.3 + n.tx_errs)
            })
    };
    let (crx, ctx, crxe, ctxe) = sum_net(cur);
    let (prx, ptx, _, _) = sum_net(prev);

    let system = SystemRate {
        cpu_pct,
        per_cpu_pct,
        mem: cur.mem,
        net_rx_bps: rate(crx, prx, secs),
        net_tx_bps: rate(ctx, ptx, secs),
        net_rx_errs: crxe,
        net_tx_errs: ctxe,
        ctxt_per_sec: rate(cur.cpu.ctxt, prev.cpu.ctxt, secs),
        procs_running: cur.cpu.procs_running,
        procs_blocked: cur.cpu.procs_blocked,
        proc_count: cur.procs.len(),
        vanished: cur.vanished,
        scan_time: cur.scan_time,
        interval,
    };

    // ---- per process ----
    let mut procs = Vec::with_capacity(cur.procs.len());
    for (key, c) in &cur.procs {
        // Lookup is by (pid, starttime). A recycled PID misses here and is
        // correctly treated as a brand new process.
        let p = prev.procs.get(key);
        let is_new = p.is_none();

        let cpu_pct = match p {
            Some(p) if secs > 0.0 => {
                let dt = c.stat.cpu_ticks().saturating_sub(p.stat.cpu_ticks());
                dt as f64 / (hz * secs) * 100.0
            }
            _ => 0.0,
        };

        let (read_bps, write_bps, rchar_bps, wchar_bps) = match (p.and_then(|p| p.io), c.io) {
            (Some(pi), Some(ci)) => (
                Some(rate(ci.read_bytes, pi.read_bytes, secs)),
                Some(rate(ci.write_bytes, pi.write_bytes, secs)),
                Some(rate(ci.rchar, pi.rchar, secs)),
                Some(rate(ci.wchar, pi.wchar, secs)),
            ),
            // Present but no prior sample: a rate is not yet defined.
            (None, Some(_)) => (Some(0.0), Some(0.0), Some(0.0), Some(0.0)),
            _ => (None, None, None, None),
        };

        procs.push(ProcRate {
            key: *key,
            pid: c.stat.pid,
            ppid: c.stat.ppid,
            comm: c.stat.comm.clone(),
            state: c.stat.state,
            threads: c.stat.num_threads,
            cpu_pct,
            rss_bytes: c.stat.rss_bytes(),
            vsize_bytes: c.stat.vsize,
            read_bps,
            write_bps,
            rchar_bps,
            wchar_bps,
            sockets: c.sockets,
            is_new,
        });
    }

    // Descending CPU, then descending RSS. Sorting here rather than in the UI
    // keeps the render path free of policy.
    procs.sort_by(|a, b| {
        b.cpu_pct
            .partial_cmp(&a.cpu_pct)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.rss_bytes.cmp(&a.rss_bytes))
    });

    Snapshot { system, procs }
}
