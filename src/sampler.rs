//! The background sampler.
//!
//! Requirement: sampling must not run on the UI thread. Spawning a thread is
//! only half of that. If the sampler took the write lock, then parsed a few
//! hundred files while holding it, the UI would block on every render and we
//! would have moved the stall rather than removed it.
//!
//! So the ordering here is deliberate:
//!
//! ```text
//!   [no lock held]  collect() ....... hundreds of file reads, ~ms
//!   [no lock held]  diff() .......... allocation and sorting
//!   [no lock held]  engine.evaluate() rule state machine
//!   [write lock]    swap in results . a few pointer moves
//! ```
//!
//! The write lock is held for the duration of a handful of moves, so a reader
//! never waits on I/O. `RwLock` rather than `Mutex` because there is one writer
//! and potentially several readers (TUI, JSON endpoint), and readers must not
//! block each other.
//!
//! Interval drift: a naive `loop { work(); sleep(interval); }` produces a period
//! of `interval + work_time`, so the sample rate silently degrades exactly when
//! the machine is busy and you most need it stable. We subtract the elapsed work
//! time from the sleep, and when work overruns the interval we skip the sleep
//! and record the overrun rather than trying to catch up with a burst.

use crate::delta::{diff, Snapshot};
use crate::ring::Ring;
use crate::rules::{Engine, Event};
use crate::sample::{Collector, Sample};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// A single point of history. Deliberately small and Copy: the ring holds
/// thousands of these and they must not carry heap allocations.
#[derive(Debug, Clone, Copy, Default)]
pub struct HistoryPoint {
    pub cpu_pct: f64,
    pub mem_pct: f64,
    pub net_rx_bps: f64,
    pub net_tx_bps: f64,
    pub proc_count: u32,
    pub scan_micros: u64,
}

// No `derive(Default)`: a Ring has no meaningful default capacity, and a
// silently-1-slot history buffer would be a nasty bug to chase.
pub struct Shared {
    pub latest: Option<Snapshot>,
    pub history: Ring<HistoryPoint>,
    pub events: Ring<Event>,
    /// (rule, subject, duration) for everything currently firing.
    pub active_alerts: Vec<(String, String, Duration)>,
    pub last_error: Option<String>,
}

pub struct SamplerHandle {
    pub shared: Arc<RwLock<Shared>>,
    stop: Arc<AtomicBool>,
    /// Number of intervals where a scan took longer than the interval itself.
    pub overruns: Arc<AtomicU64>,
    pub ticks: Arc<AtomicU64>,
    thread: Option<JoinHandle<()>>,
}

impl SamplerHandle {
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for SamplerHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

pub struct SamplerConfig {
    pub interval: Duration,
    pub history_len: usize,
    pub event_log_len: usize,
}

impl Default for SamplerConfig {
    fn default() -> Self {
        SamplerConfig {
            interval: Duration::from_secs(1),
            history_len: 300,
            event_log_len: 200,
        }
    }
}

pub fn spawn(collector: Collector, engine: Engine, cfg: SamplerConfig) -> SamplerHandle {
    let shared = Arc::new(RwLock::new(Shared {
        latest: None,
        history: Ring::new(cfg.history_len),
        events: Ring::new(cfg.event_log_len),
        active_alerts: Vec::new(),
        last_error: None,
    }));
    let stop = Arc::new(AtomicBool::new(false));
    let overruns = Arc::new(AtomicU64::new(0));
    let ticks = Arc::new(AtomicU64::new(0));

    let t_shared = Arc::clone(&shared);
    let t_stop = Arc::clone(&stop);
    let t_overruns = Arc::clone(&overruns);
    let t_ticks = Arc::clone(&ticks);
    let interval = cfg.interval;
    let mut engine = engine;

    let thread = std::thread::Builder::new()
        .name("vitals-sampler".into())
        .spawn(move || {
            let mut prev: Option<Sample> = None;

            while !t_stop.load(Ordering::Relaxed) {
                let cycle_start = Instant::now();

                // ---- all real work happens with NO lock held ----
                let result = collector.collect();
                let (snapshot, events, err) = match result {
                    Ok(cur) => {
                        let out = match &prev {
                            Some(p) => {
                                let snap = diff(p, &cur);
                                let evs = engine.evaluate(&snap, Instant::now());
                                (Some(snap), evs, None)
                            }
                            // The first sample establishes a baseline; rates are
                            // undefined until there are two.
                            None => (None, Vec::new(), None),
                        };
                        prev = Some(cur);
                        out
                    }
                    Err(e) => (None, Vec::new(), Some(e.to_string())),
                };

                let point = snapshot.as_ref().map(|s| HistoryPoint {
                    cpu_pct: s.system.cpu_pct,
                    mem_pct: s.system.mem.used_pct(),
                    net_rx_bps: s.system.net_rx_bps,
                    net_tx_bps: s.system.net_tx_bps,
                    proc_count: s.system.proc_count as u32,
                    scan_micros: s.system.scan_time.as_micros() as u64,
                });
                let active = engine.active().into_iter().map(|(r, s, d, _)| (r, s, d)).collect();

                // ---- lock held only for the handover ----
                {
                    let mut g = t_shared.write().unwrap();
                    if let Some(p) = point {
                        g.history.push(p);
                    }
                    for e in events {
                        g.events.push(e);
                    }
                    if snapshot.is_some() {
                        g.latest = snapshot;
                    }
                    g.active_alerts = active;
                    g.last_error = err;
                }
                t_ticks.fetch_add(1, Ordering::Relaxed);

                // ---- drift-corrected sleep ----
                let spent = cycle_start.elapsed();
                match interval.checked_sub(spent) {
                    Some(rest) if !rest.is_zero() => {
                        // Wake early enough to notice a stop request promptly.
                        let deadline = Instant::now() + rest;
                        while Instant::now() < deadline {
                            if t_stop.load(Ordering::Relaxed) {
                                return;
                            }
                            let left = deadline.saturating_duration_since(Instant::now());
                            std::thread::sleep(left.min(Duration::from_millis(50)));
                        }
                    }
                    _ => {
                        // Scan took at least as long as the interval. Do not try
                        // to catch up: that would queue scans back-to-back and
                        // make the monitor part of the problem it is reporting.
                        t_overruns.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        })
        .expect("failed to spawn sampler thread");

    SamplerHandle { shared, stop, overruns, ticks, thread: Some(thread) }
}
