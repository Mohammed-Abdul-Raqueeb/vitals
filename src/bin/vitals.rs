//! vitals command line.
//!
//! Three output modes over the same sampler:
//!   * default    — live terminal view, redrawn each interval
//!   * --once     — one snapshot to stdout, for scripts
//!   * --json     — machine-readable, one JSON object per interval
//!
//! The terminal view uses plain ANSI escapes and no alternate screen buffer.
//! That is a deliberate limitation: catching SIGINT to restore the terminal
//! needs a signal handler, which needs libc, which would break the
//! zero-dependency property. Without a handler, an alternate screen would leave
//! the user's terminal wrecked on Ctrl-C. Redrawing in the normal buffer is
//! slightly less pretty and always safe. Interactive key handling (sort keys,
//! kill) is out for the same reason — it needs termios.

use std::io::Write;
use std::time::{Duration, Instant};
use vitals::rules::{Engine, EventKind};
use vitals::sample::Collector;
use vitals::sampler::{self, SamplerConfig};
use vitals::units::{human_bytes, human_rate, parse_duration};

fn usage() -> ! {
    eprintln!(
        "vitals — live per-process resource monitor with alerting

USAGE:
  vitals [--interval 1s] [--top N] [--rules FILE] [--sockets]
         [--once | --json] [--duration 30s] [--proc-root DIR]

OPTIONS:
  --interval D    sampling interval               (default 1s)
  --top N         processes to display            (default 15)
  --rules FILE    alert rule file; see docs       (default: none)
  --sockets       attribute open sockets to pids  (costly; see DESIGN.md)
  --once          print one snapshot and exit
  --json          emit one JSON object per interval
  --duration D    run for D then exit             (default: forever)
  --proc-root DIR read this instead of /proc      (for testing)
"
    );
    std::process::exit(2)
}

fn flag(a: &[String], k: &str) -> Option<String> {
    a.iter().position(|x| x == k).and_then(|i| a.get(i + 1).cloned())
}
fn has(a: &[String], k: &str) -> bool {
    a.iter().any(|x| x == k)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if has(&args, "--help") || has(&args, "-h") {
        usage();
    }

    let interval = flag(&args, "--interval")
        .and_then(|s| parse_duration(&s))
        .unwrap_or(Duration::from_secs(1));
    let top: usize = flag(&args, "--top").and_then(|s| s.parse().ok()).unwrap_or(15);
    let root = flag(&args, "--proc-root").unwrap_or_else(|| "/proc".into());
    let json = has(&args, "--json");
    let once = has(&args, "--once");
    let run_for = flag(&args, "--duration").and_then(|s| parse_duration(&s));

    // ---- alert rules ----
    let mut engine_rules = Vec::new();
    if let Some(path) = flag(&args, "--rules") {
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let (rules, errs) = vitals::rules::parse_rules(&text);
                for e in &errs {
                    eprintln!("vitals: rule file {}: {}", path, e);
                }
                if !errs.is_empty() && rules.is_empty() {
                    eprintln!("vitals: no usable rules; exiting");
                    std::process::exit(1);
                }
                eprintln!("vitals: loaded {} alert rule(s) from {}", rules.len(), path);
                engine_rules = rules;
            }
            Err(e) => {
                eprintln!("vitals: cannot read {}: {}", path, e);
                std::process::exit(1);
            }
        }
    }

    let mut collector = Collector::new(&root);
    collector.with_sockets = has(&args, "--sockets");

    let handle = sampler::spawn(
        collector,
        Engine::new(engine_rules),
        SamplerConfig { interval, history_len: 300, event_log_len: 200 },
    );

    // Rates need two samples, so the first useful output is one interval away.
    std::thread::sleep(interval + Duration::from_millis(120));

    let start = Instant::now();
    let mut out = std::io::stdout();
    loop {
        {
            let g = handle.shared.read().unwrap();
            if let Some(err) = &g.last_error {
                eprintln!("vitals: sample error: {}", err);
            }
            match &g.latest {
                None => eprintln!("vitals: waiting for first sample..."),
                Some(snap) => {
                    if json {
                        let _ = writeln!(out, "{}", render_json(snap, &g, top));
                    } else {
                        let text = render_text(snap, &g, top, once);
                        if once {
                            let _ = write!(out, "{}", text);
                        } else {
                            // Home + clear-to-end, rather than a full clear, to
                            // avoid the flicker a \x1b[2J causes every frame.
                            let _ = write!(out, "\x1b[H\x1b[J{}", text);
                        }
                    }
                    let _ = out.flush();
                }
            }
        }
        if once {
            break;
        }
        if let Some(d) = run_for {
            if start.elapsed() >= d {
                break;
            }
        }
        std::thread::sleep(interval);
    }
    handle.stop();
}

// ------------------------------------------------------------------ render --

const BLOCKS: [char; 8] = ['\u{2581}', '\u{2582}', '\u{2583}', '\u{2584}', '\u{2585}', '\u{2586}', '\u{2587}', '\u{2588}'];

/// Render values 0..=max as a one-line sparkline.
fn sparkline(vals: &[f64], max: f64) -> String {
    if vals.is_empty() {
        return String::new();
    }
    let max = if max <= 0.0 { 1.0 } else { max };
    vals.iter()
        .map(|v| {
            let f = (v / max).clamp(0.0, 1.0);
            BLOCKS[((f * (BLOCKS.len() - 1) as f64).round()) as usize]
        })
        .collect()
}

fn render_text(
    snap: &vitals::delta::Snapshot,
    shared: &sampler::Shared,
    top: usize,
    plain: bool,
) -> String {
    let mut s = String::with_capacity(4096);
    let sys = &snap.system;

    let hist: Vec<f64> = shared.history.iter_chrono().map(|h| h.cpu_pct).collect();
    let tail = &hist[hist.len().saturating_sub(60)..];

    s.push_str(&format!(
        "vitals   cpu {:>5.1}%  mem {:>5.1}% ({} / {})  net rx {:>9} tx {:>9}\n",
        sys.cpu_pct,
        sys.mem.used_pct(),
        human_bytes(sys.mem.used()),
        human_bytes(sys.mem.total),
        human_rate(sys.net_rx_bps),
        human_rate(sys.net_tx_bps),
    ));
    if !plain {
        s.push_str(&format!("cpu 60s  {}\n", sparkline(tail, 100.0)));
    }
    s.push_str(&format!(
        "procs {}  running {}  blocked {}  ctxsw {:.0}/s  vanished {}  scan {:.1}ms  interval {:.0}ms\n",
        sys.proc_count,
        sys.procs_running,
        sys.procs_blocked,
        sys.ctxt_per_sec,
        sys.vanished,
        sys.scan_time.as_secs_f64() * 1000.0,
        sys.interval.as_secs_f64() * 1000.0,
    ));

    // Per-core bar, when there is more than one.
    if sys.per_cpu_pct.len() > 1 {
        s.push_str("cores    ");
        for (i, p) in sys.per_cpu_pct.iter().enumerate() {
            s.push_str(&format!("{}:{:>3.0}% ", i, p));
        }
        s.push('\n');
    }

    // ---- alerts ----
    if !shared.active_alerts.is_empty() {
        s.push_str(&format!("\nACTIVE ALERTS ({})\n", shared.active_alerts.len()));
        for (rule, subject, dur) in shared.active_alerts.iter().take(8) {
            s.push_str(&format!("  ! {:<16} {:<28} firing {:.0}s\n", rule, subject, dur.as_secs_f64()));
        }
    }
    let recent: Vec<_> = shared.events.iter_chrono().collect();
    if !recent.is_empty() {
        s.push_str("\nRECENT EVENTS\n");
        for e in recent.iter().rev().take(5) {
            let tag = match e.kind {
                EventKind::Fired => "FIRED  ",
                EventKind::Cleared => "CLEARED",
                EventKind::ClearedGone => "GONE   ",
            };
            s.push_str(&format!(
                "  {} {:<16} {:<26} {}={:.1} (thr {:.1}) after {:.0}s\n",
                tag,
                e.rule_name,
                e.subject,
                e.metric.name(),
                e.value,
                e.threshold,
                e.held_for.as_secs_f64()
            ));
        }
    }

    // ---- process table ----
    s.push_str(&format!(
        "\n{:>7} {:>7} {:>6} {:>9} {:>3} {:>10} {:>10}  {}\n",
        "PID", "PPID", "CPU%", "RSS", "TH", "DISK R", "DISK W", "COMMAND"
    ));
    for p in snap.procs.iter().take(top) {
        let r = p.read_bps.map(human_rate).unwrap_or_else(|| "n/a".into());
        let w = p.write_bps.map(human_rate).unwrap_or_else(|| "n/a".into());
        s.push_str(&format!(
            "{:>7} {:>7} {:>6.1} {:>9} {:>3} {:>10} {:>10}  {}{}\n",
            p.pid,
            p.ppid,
            p.cpu_pct,
            human_bytes(p.rss_bytes),
            p.threads,
            r,
            w,
            p.comm,
            if p.state == 'Z' { " <zombie>" } else { "" },
        ));
    }
    s
}

// -------------------------------------------------------------------- json --

/// Escape a string for JSON. `comm` comes from the kernel and can contain
/// quotes, backslashes and control bytes, so this is not optional.
fn jstr(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn jnum(v: f64) -> String {
    if v.is_finite() {
        format!("{:.3}", v)
    } else {
        "null".into()
    }
}

fn render_json(
    snap: &vitals::delta::Snapshot,
    shared: &sampler::Shared,
    top: usize,
) -> String {
    let sys = &snap.system;
    let mut s = String::with_capacity(4096);
    s.push_str("{\"system\":{");
    s.push_str(&format!("\"cpu_pct\":{},", jnum(sys.cpu_pct)));
    s.push_str(&format!("\"mem_pct\":{},", jnum(sys.mem.used_pct())));
    s.push_str(&format!("\"mem_used\":{},", sys.mem.used()));
    s.push_str(&format!("\"mem_total\":{},", sys.mem.total));
    s.push_str(&format!("\"net_rx_bps\":{},", jnum(sys.net_rx_bps)));
    s.push_str(&format!("\"net_tx_bps\":{},", jnum(sys.net_tx_bps)));
    s.push_str(&format!("\"proc_count\":{},", sys.proc_count));
    s.push_str(&format!("\"vanished\":{},", sys.vanished));
    s.push_str(&format!("\"scan_micros\":{}", sys.scan_time.as_micros()));
    s.push_str("},\"procs\":[");
    for (i, p) in snap.procs.iter().take(top).enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!(
            "{{\"pid\":{},\"ppid\":{},\"comm\":{},\"cpu_pct\":{},\"rss\":{},\"threads\":{},\"read_bps\":{},\"write_bps\":{}}}",
            p.pid,
            p.ppid,
            jstr(&p.comm),
            jnum(p.cpu_pct),
            p.rss_bytes,
            p.threads,
            p.read_bps.map(jnum).unwrap_or_else(|| "null".into()),
            p.write_bps.map(jnum).unwrap_or_else(|| "null".into()),
        ));
    }
    s.push_str("],\"alerts\":[");
    for (i, (rule, subject, dur)) in shared.active_alerts.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!(
            "{{\"rule\":{},\"subject\":{},\"firing_secs\":{}}}",
            jstr(rule),
            jstr(subject),
            jnum(dur.as_secs_f64())
        ));
    }
    s.push_str("]}");
    s
}
