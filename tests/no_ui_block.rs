//! Empirical proof that the UI thread never blocks on sampling.
//!
//! This is the requirement stated in the brief: "keeping the sampler off the
//! UI thread." Spawning a background thread is necessary but not sufficient —
//! if that thread held the shared lock while doing its I/O, a reader would
//! still stall for the full scan duration. This test proves the actual
//! property: while a scan is in flight, a concurrent reader's lock acquisition
//! stays fast, even when the scan itself is slow.
//!
//! It points the real collector at a synthetic /proc tree with thousands of
//! process directories (built by scripts/make_big_proc_fixture.py) so a single
//! scan takes tens of milliseconds — long enough that any lock-holding-during-IO
//! bug would be trivially visible as a multi-millisecond read stall.
//!
//! Set VITALS_BIG_PROC_ROOT to the fixture directory to run this test; it is
//! `#[ignore]`d by default because the fixture is generated out of band and is
//! not something a plain `cargo test` should require.

use std::time::{Duration, Instant};
use vitals::rules::Engine;
use vitals::sample::Collector;
use vitals::sampler::{self, SamplerConfig};

#[test]
#[ignore = "requires VITALS_BIG_PROC_ROOT; see scripts/make_big_proc_fixture.py"]
fn reader_lock_stays_fast_while_a_slow_scan_is_in_flight() {
    let root = std::env::var("VITALS_BIG_PROC_ROOT")
        .expect("set VITALS_BIG_PROC_ROOT to a large fixture directory");

    // Confirm the fixture is actually big enough to make the claim meaningful.
    let probe = Collector::new(&root).collect().expect("fixture must be readable");
    assert!(
        probe.procs.len() > 500,
        "fixture only has {} processes; too small to produce a slow scan",
        probe.procs.len()
    );
    eprintln!(
        "fixture: {} processes, single scan took {:.1}ms",
        probe.procs.len(),
        probe.scan_time.as_secs_f64() * 1000.0
    );
    assert!(
        probe.scan_time > Duration::from_millis(5),
        "scan of {:?} took only {:?}; too fast for this test to prove anything \
         (increase the process count in the fixture)",
        root,
        probe.scan_time
    );

    let handle = sampler::spawn(
        Collector::new(&root),
        Engine::new(vec![]),
        SamplerConfig { interval: Duration::from_millis(1), history_len: 60, event_log_len: 10 },
    );

    // Hammer the read lock from this thread for a couple of seconds while the
    // sampler is continuously scanning the large fixture in the background.
    let mut worst = Duration::ZERO;
    let mut samples = 0u32;
    let mut total = Duration::ZERO;
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        let t0 = Instant::now();
        {
            let g = handle.shared.read().unwrap();
            std::hint::black_box(&g.latest);
        }
        let waited = t0.elapsed();
        worst = worst.max(waited);
        total += waited;
        samples += 1;
        // No sleep: this is deliberately adversarial, acquiring the lock as
        // fast as possible to maximise the chance of catching contention.
    }

    let avg = total / samples.max(1);
    eprintln!(
        "reader: {} lock acquisitions, avg {:?}, worst {:?} (scan takes ~{:.1}ms)",
        samples,
        avg,
        worst,
        probe.scan_time.as_secs_f64() * 1000.0
    );

    // The bar: worst-case reader latency must stay far below a single scan's
    // duration. If the sampler held the lock across its I/O, worst-case would
    // converge on the scan time (tens of ms); instead it should stay in the
    // tens-of-microseconds range regardless of how slow the scan is.
    assert!(
        worst < probe.scan_time / 4,
        "reader stalled for {:?}, which is not far below one scan ({:?}) — \
         the lock is being held across I/O",
        worst,
        probe.scan_time
    );

    handle.stop();
}
