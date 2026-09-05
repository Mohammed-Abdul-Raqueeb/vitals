//! System constants and formatting.
//!
//! `/proc/[pid]/stat` reports CPU time in *clock ticks* and memory in *pages*.
//! Neither unit is meaningful until you know USER_HZ and the page size. The
//! usual way to get them is `sysconf(_SC_CLK_TCK)` and `sysconf(_SC_PAGESIZE)`
//! from libc.
//!
//! We read them out of `/proc/self/auxv` instead. The kernel hands every process
//! an auxiliary vector at exec time — a flat array of (key: u64, value: u64)
//! pairs terminated by AT_NULL — and it contains both values. That keeps this
//! crate on the standard library alone.
//!
//! Hardcoding 100 and 4096 would be wrong: USER_HZ is a kernel build option
//! (CONFIG_HZ can be 100, 250, 300 or 1000), and page size is 16 KiB on some
//! arm64 kernels. Getting it from the kernel is both correct and cheap, since
//! it happens once at startup.

use std::sync::OnceLock;

const AT_NULL: u64 = 0;
const AT_PAGESZ: u64 = 6;
const AT_CLKTCK: u64 = 17;

#[derive(Debug, Clone, Copy)]
pub struct SysConst {
    /// Clock ticks per second (USER_HZ). CPU times in /proc are in these units.
    pub clk_tck: u64,
    /// Bytes per page. RSS in /proc/[pid]/stat is in these units.
    pub page_size: u64,
    /// Number of online CPUs, from the `cpuN` lines of /proc/stat.
    pub ncpu: usize,
}

fn parse_auxv(bytes: &[u8]) -> (Option<u64>, Option<u64>) {
    let mut clk = None;
    let mut page = None;
    for pair in bytes.chunks_exact(16) {
        let k = u64::from_ne_bytes(pair[0..8].try_into().unwrap());
        let v = u64::from_ne_bytes(pair[8..16].try_into().unwrap());
        match k {
            AT_NULL => break,
            AT_CLKTCK => clk = Some(v),
            AT_PAGESZ => page = Some(v),
            _ => {}
        }
    }
    (clk, page)
}

/// Count `cpuN` lines in /proc/stat. The aggregate line is `cpu ` with two
/// spaces, so requiring a digit after the prefix excludes it.
pub fn count_cpus(proc_stat: &str) -> usize {
    proc_stat
        .lines()
        .filter(|l| {
            l.strip_prefix("cpu")
                .and_then(|r| r.chars().next())
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
        })
        .count()
        .max(1)
}

static CONSTS: OnceLock<SysConst> = OnceLock::new();

pub fn sys_const() -> SysConst {
    *CONSTS.get_or_init(|| {
        let (clk, page) = std::fs::read("/proc/self/auxv")
            .map(|b| parse_auxv(&b))
            .unwrap_or((None, None));
        let ncpu = std::fs::read_to_string("/proc/stat")
            .map(|s| count_cpus(&s))
            .unwrap_or(1);
        SysConst {
            // Fall back to the near-universal defaults only if auxv is absent.
            clk_tck: clk.filter(|v| *v > 0).unwrap_or(100),
            page_size: page.filter(|v| *v > 0).unwrap_or(4096),
            ncpu,
        }
    })
}

// ------------------------------------------------------------- formatting --

pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "K", "M", "G", "T", "P"];
    if n < 1024 {
        return format!("{}B", n);
    }
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if v >= 100.0 {
        format!("{:.0}{}", v, UNITS[i])
    } else {
        format!("{:.1}{}", v, UNITS[i])
    }
}

pub fn human_rate(bytes_per_sec: f64) -> String {
    if bytes_per_sec < 1.0 {
        return "-".into();
    }
    format!("{}/s", human_bytes(bytes_per_sec as u64))
}

/// Parse sizes written as `500MB`, `2G`, `1024`. Used by the rule parser.
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, mult) = if let Some(p) = s.strip_suffix("GB").or_else(|| s.strip_suffix('G')) {
        (p, 1u64 << 30)
    } else if let Some(p) = s.strip_suffix("MB").or_else(|| s.strip_suffix('M')) {
        (p, 1u64 << 20)
    } else if let Some(p) = s.strip_suffix("KB").or_else(|| s.strip_suffix('K')) {
        (p, 1u64 << 10)
    } else if let Some(p) = s.strip_suffix('B') {
        (p, 1)
    } else {
        (s, 1)
    };
    let v: f64 = num.trim().parse().ok()?;
    if v < 0.0 {
        return None;
    }
    Some((v * mult as f64) as u64)
}

/// Parse durations written as `5s`, `2m`, `500ms`, `30`.
pub fn parse_duration(s: &str) -> Option<std::time::Duration> {
    let s = s.trim();
    let (num, scale_ms) = if let Some(p) = s.strip_suffix("ms") {
        (p, 1.0)
    } else if let Some(p) = s.strip_suffix('s') {
        (p, 1000.0)
    } else if let Some(p) = s.strip_suffix('m') {
        (p, 60_000.0)
    } else if let Some(p) = s.strip_suffix('h') {
        (p, 3_600_000.0)
    } else {
        (s, 1000.0)
    };
    let v: f64 = num.trim().parse().ok()?;
    if v < 0.0 {
        return None;
    }
    Some(std::time::Duration::from_millis((v * scale_ms) as u64))
}
