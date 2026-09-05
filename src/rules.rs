//! User-defined alert rules.
//!
//! Rule syntax, one per line:
//!
//! ```text
//!   alert <name> <target> <metric> <op> <value> for <duration> [clear <value>]
//!
//!   alert high_cpu   system         cpu_pct  >  80      for 5s   clear 60
//!   alert cpu_hog    process:*      cpu_pct  >  50      for 3s
//!   alert node_leak  process:node   rss      >  500MB   for 30s  clear 400MB
//!   alert low_mem    system         mem_pct  >  90      for 10s
//!   alert disk_burst process:*       write_bps > 50MB   for 2s
//! ```
//!
//! Two mechanisms keep this from producing an alert storm, and they solve
//! different problems:
//!
//! * **`for <duration>` (sustain).** The condition must hold continuously for
//!   that long before the alert fires. This suppresses transients — a compiler
//!   spiking to 100% for one sample is not an incident.
//!
//! * **`clear <value>` (hysteresis).** The alert fires above the threshold but
//!   only clears below a *lower* one. Without it, a process oscillating around
//!   80.0% fires and clears on alternate samples forever. This is the same idea
//!   as a thermostat's deadband, and naming it that in an interview lands well.
//!
//! The state machine per (rule, subject):
//!
//! ```text
//!   Inactive --cond true--> Pending --held for D--> Firing
//!      ^                       |                       |
//!      |                  cond false              cond below clear
//!      +-----------------------+-----------------------+
//! ```
//!
//! A subject that disappears while firing (the process exited) clears the alert
//! with an explicit reason, rather than leaving it stuck on forever.

use crate::delta::Snapshot;
use crate::units::{parse_duration, parse_size};
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Metric {
    CpuPct,
    MemPct,
    Rss,
    ReadBps,
    WriteBps,
    NetRxBps,
    NetTxBps,
    Threads,
    ProcCount,
}

impl Metric {
    fn parse(s: &str) -> Option<Metric> {
        Some(match s {
            "cpu_pct" | "cpu" => Metric::CpuPct,
            "mem_pct" => Metric::MemPct,
            "rss" | "rss_bytes" | "mem" => Metric::Rss,
            "read_bps" => Metric::ReadBps,
            "write_bps" => Metric::WriteBps,
            "net_rx_bps" => Metric::NetRxBps,
            "net_tx_bps" => Metric::NetTxBps,
            "threads" => Metric::Threads,
            "proc_count" => Metric::ProcCount,
            _ => return None,
        })
    }
    /// Byte-valued metrics accept suffixes like `500MB`; the rest are plain.
    fn is_bytes(&self) -> bool {
        matches!(
            self,
            Metric::Rss
                | Metric::ReadBps
                | Metric::WriteBps
                | Metric::NetRxBps
                | Metric::NetTxBps
        )
    }
    fn applies_to_process(&self) -> bool {
        matches!(
            self,
            Metric::CpuPct | Metric::Rss | Metric::ReadBps | Metric::WriteBps | Metric::Threads
        )
    }
    pub fn name(&self) -> &'static str {
        match self {
            Metric::CpuPct => "cpu_pct",
            Metric::MemPct => "mem_pct",
            Metric::Rss => "rss",
            Metric::ReadBps => "read_bps",
            Metric::WriteBps => "write_bps",
            Metric::NetRxBps => "net_rx_bps",
            Metric::NetTxBps => "net_tx_bps",
            Metric::Threads => "threads",
            Metric::ProcCount => "proc_count",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Gt,
    Lt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    System,
    /// Match on the `comm` field. `*` matches every process.
    Process(String),
}

impl Target {
    fn matches(&self, comm: &str) -> bool {
        match self {
            Target::System => false,
            Target::Process(p) => p == "*" || p == comm,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub target: Target,
    pub metric: Metric,
    pub op: Op,
    pub threshold: f64,
    pub sustain: Duration,
    /// Hysteresis boundary. Defaults to `threshold` (no deadband) when absent.
    pub clear: f64,
}

// ------------------------------------------------------------------ parsing --

#[derive(Debug)]
pub struct ParseError {
    pub line_no: usize,
    pub line: String,
    pub reason: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {} (in: {:?})", self.line_no, self.reason, self.line)
    }
}

fn parse_value(tok: &str, metric: Metric) -> Option<f64> {
    if metric.is_bytes() {
        // Accept both `500MB` and a bare number of bytes.
        parse_size(tok).map(|v| v as f64).or_else(|| tok.parse().ok())
    } else {
        tok.parse().ok()
    }
}

pub fn parse_rules(text: &str) -> (Vec<Rule>, Vec<ParseError>) {
    let mut rules = Vec::new();
    let mut errs = Vec::new();

    for (i, raw) in text.lines().enumerate() {
        let line_no = i + 1;
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let t: Vec<&str> = line.split_ascii_whitespace().collect();

        let mut err = |reason: &str| {
            errs.push(ParseError {
                line_no,
                line: raw.to_string(),
                reason: reason.to_string(),
            })
        };

        if t.first() != Some(&"alert") {
            err("expected a line beginning with `alert`");
            continue;
        }
        if t.len() < 8 {
            err("too few fields; expected: alert <name> <target> <metric> <op> <value> for <dur>");
            continue;
        }

        let name = t[1].to_string();
        let target = if t[2] == "system" {
            Target::System
        } else if let Some(p) = t[2].strip_prefix("process:") {
            if p.is_empty() {
                err("empty process pattern");
                continue;
            }
            Target::Process(p.to_string())
        } else {
            err("target must be `system` or `process:<comm>` (or `process:*`)");
            continue;
        };

        let metric = match Metric::parse(t[3]) {
            Some(m) => m,
            None => {
                err("unknown metric");
                continue;
            }
        };
        if matches!(target, Target::Process(_)) && !metric.applies_to_process() {
            err("that metric is system-wide and cannot be scoped to a process");
            continue;
        }

        let op = match t[4] {
            ">" => Op::Gt,
            "<" => Op::Lt,
            _ => {
                err("operator must be > or <");
                continue;
            }
        };

        let threshold = match parse_value(t[5], metric) {
            Some(v) => v,
            None => {
                err("could not parse threshold value");
                continue;
            }
        };

        if t[6] != "for" {
            err("expected keyword `for` before the duration");
            continue;
        }
        let sustain = match parse_duration(t[7]) {
            Some(d) => d,
            None => {
                err("could not parse duration");
                continue;
            }
        };

        // Optional: clear <value>
        let mut clear = threshold;
        if t.len() > 8 {
            if t[8] != "clear" || t.len() < 10 {
                err("trailing tokens; expected `clear <value>`");
                continue;
            }
            match parse_value(t[9], metric) {
                Some(v) => clear = v,
                None => {
                    err("could not parse clear value");
                    continue;
                }
            }
            // A deadband on the wrong side never clears: the alert would latch on.
            let sane = match op {
                Op::Gt => clear <= threshold,
                Op::Lt => clear >= threshold,
            };
            if !sane {
                err("clear value is on the wrong side of the threshold; the alert could never clear");
                continue;
            }
        }

        rules.push(Rule { name, target, metric, op, threshold, sustain, clear });
    }
    (rules, errs)
}

// ---------------------------------------------------------------- engine --

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubjectId {
    pub rule: usize,
    /// None for system-wide rules; Some((pid, starttime)) for per-process.
    pub proc_key: Option<(i32, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Pending,
    Firing,
}

#[derive(Debug, Clone)]
struct State {
    phase: Phase,
    since: Instant,
    /// Marks subjects seen this tick, so vanished ones can be reaped.
    seen: u64,
    label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKind {
    Fired,
    Cleared,
    /// The process being watched exited while the alert was active.
    ClearedGone,
}

#[derive(Debug, Clone)]
pub struct Event {
    pub kind: EventKind,
    pub rule_name: String,
    pub subject: String,
    pub metric: Metric,
    pub value: f64,
    pub threshold: f64,
    pub held_for: Duration,
}

pub struct Engine {
    pub rules: Vec<Rule>,
    states: HashMap<SubjectId, State>,
    tick: u64,
}

impl Engine {
    pub fn new(rules: Vec<Rule>) -> Self {
        Engine { rules, states: HashMap::new(), tick: 0 }
    }

    pub fn active_count(&self) -> usize {
        self.states.values().filter(|s| s.phase == Phase::Firing).count()
    }

    pub fn active(&self) -> Vec<(String, String, Duration, Instant)> {
        let mut v: Vec<_> = self
            .states
            .iter()
            .filter(|(_, s)| s.phase == Phase::Firing)
            .map(|(k, s)| {
                (
                    self.rules[k.rule].name.clone(),
                    s.label.clone(),
                    s.since.elapsed(),
                    s.since,
                )
            })
            .collect();
        v.sort_by(|a, b| b.2.cmp(&a.2));
        v
    }

    fn system_value(rule: &Rule, s: &Snapshot) -> Option<f64> {
        Some(match rule.metric {
            Metric::CpuPct => s.system.cpu_pct,
            Metric::MemPct => s.system.mem.used_pct(),
            Metric::NetRxBps => s.system.net_rx_bps,
            Metric::NetTxBps => s.system.net_tx_bps,
            Metric::ProcCount => s.system.proc_count as f64,
            _ => return None,
        })
    }

    /// Evaluate every rule against a snapshot. `now` is injected rather than
    /// read from the clock so the sustain and hysteresis logic can be tested
    /// deterministically instead of with `sleep`.
    pub fn evaluate(&mut self, snap: &Snapshot, now: Instant) -> Vec<Event> {
        self.tick += 1;
        let tick = self.tick;
        let mut events = Vec::new();

        for (ri, rule) in self.rules.iter().enumerate() {
            match &rule.target {
                Target::System => {
                    if let Some(v) = Self::system_value(rule, snap) {
                        let id = SubjectId { rule: ri, proc_key: None };
                        Self::step(
                            &mut self.states, &mut events, id, rule, "system".into(), v, now, tick,
                        );
                    }
                }
                Target::Process(_) => {
                    for p in &snap.procs {
                        if !rule.target.matches(&p.comm) {
                            continue;
                        }
                        // A brand new process has no meaningful rate yet.
                        if p.is_new {
                            continue;
                        }
                        let v = match rule.metric {
                            Metric::CpuPct => p.cpu_pct,
                            Metric::Rss => p.rss_bytes as f64,
                            Metric::ReadBps => match p.read_bps {
                                Some(v) => v,
                                None => continue, // unreadable, not zero
                            },
                            Metric::WriteBps => match p.write_bps {
                                Some(v) => v,
                                None => continue,
                            },
                            Metric::Threads => p.threads as f64,
                            _ => continue,
                        };
                        let id = SubjectId {
                            rule: ri,
                            proc_key: Some((p.key.pid, p.key.starttime)),
                        };
                        let label = format!("{} (pid {})", p.comm, p.pid);
                        Self::step(
                            &mut self.states, &mut events, id, rule, label, v, now, tick,
                        );
                    }
                }
            }
        }

        // Reap subjects not seen this tick. For a process rule that means the
        // process exited; a firing alert must clear rather than latch forever.
        let rules = &self.rules;
        self.states.retain(|id, st| {
            if st.seen == tick {
                return true;
            }
            if st.phase == Phase::Firing {
                events.push(Event {
                    kind: EventKind::ClearedGone,
                    rule_name: rules[id.rule].name.clone(),
                    subject: st.label.clone(),
                    metric: rules[id.rule].metric,
                    value: 0.0,
                    threshold: rules[id.rule].threshold,
                    held_for: now.saturating_duration_since(st.since),
                });
            }
            false
        });

        events
    }

    #[allow(clippy::too_many_arguments)]
    fn step(
        states: &mut HashMap<SubjectId, State>,
        events: &mut Vec<Event>,
        id: SubjectId,
        rule: &Rule,
        label: String,
        value: f64,
        now: Instant,
        tick: u64,
    ) {
        let breaching = match rule.op {
            Op::Gt => value > rule.threshold,
            Op::Lt => value < rule.threshold,
        };
        // Hysteresis: while firing, stay firing until the value crosses the
        // (lower, for `>`) clear boundary — not merely back under the threshold.
        let still_active = match rule.op {
            Op::Gt => value > rule.clear,
            Op::Lt => value < rule.clear,
        };

        match states.get_mut(&id) {
            None => {
                if breaching {
                    if rule.sustain.is_zero() {
                        states.insert(
                            id,
                            State { phase: Phase::Firing, since: now, seen: tick, label: label.clone() },
                        );
                        events.push(Event {
                            kind: EventKind::Fired,
                            rule_name: rule.name.clone(),
                            subject: label,
                            metric: rule.metric,
                            value,
                            threshold: rule.threshold,
                            held_for: Duration::ZERO,
                        });
                    } else {
                        states.insert(
                            id,
                            State { phase: Phase::Pending, since: now, seen: tick, label },
                        );
                    }
                }
            }
            Some(st) => {
                st.seen = tick;
                st.label = label.clone();
                match st.phase {
                    Phase::Pending => {
                        if !breaching {
                            // Transient. Drop the pending state entirely; the
                            // sustain timer restarts from scratch next breach.
                            states.remove(&id);
                        } else if now.saturating_duration_since(st.since) >= rule.sustain {
                            st.phase = Phase::Firing;
                            let held = now.saturating_duration_since(st.since);
                            st.since = now;
                            events.push(Event {
                                kind: EventKind::Fired,
                                rule_name: rule.name.clone(),
                                subject: label,
                                metric: rule.metric,
                                value,
                                threshold: rule.threshold,
                                held_for: held,
                            });
                        }
                    }
                    Phase::Firing => {
                        if !still_active {
                            let held = now.saturating_duration_since(st.since);
                            events.push(Event {
                                kind: EventKind::Cleared,
                                rule_name: rule.name.clone(),
                                subject: label,
                                metric: rule.metric,
                                value,
                                threshold: rule.clear,
                                held_for: held,
                            });
                            states.remove(&id);
                        }
                    }
                }
            }
        }
    }
}
