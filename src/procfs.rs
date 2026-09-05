//! Parsers for the /proc files we read.
//!
//! Every function here is a pure function from `&str` to a value. None of them
//! touch the filesystem. That is deliberate: the awkward cases in procfs parsing
//! are all about *content*, so being able to write them as string literals in a
//! test is worth more than any amount of filesystem mocking.
//!
//! The kernel's authoritative description of these formats is `proc(5)`.

use crate::units::sys_const;

// ------------------------------------------------------------ /proc/stat --

/// One CPU's cumulative time, in clock ticks since boot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CpuTimes {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
    pub guest: u64,
    pub guest_nice: u64,
}

impl CpuTimes {
    /// Total ticks accounted for.
    ///
    /// `guest` and `guest_nice` are deliberately excluded: the kernel already
    /// counts guest time inside `user`, and guest_nice inside `nice`. Adding
    /// them again inflates the denominator and makes every CPU percentage read
    /// low on a machine running VMs. This is a real bug in monitoring code and
    /// an easy thing to be asked about.
    pub fn total(&self) -> u64 {
        self.user
            + self.nice
            + self.system
            + self.idle
            + self.iowait
            + self.irq
            + self.softirq
            + self.steal
    }

    /// Time not spent idle. `iowait` counts as idle: the CPU was available, it
    /// just had nothing runnable. Counting it as busy is the other common error.
    pub fn busy(&self) -> u64 {
        self.total() - self.idle - self.iowait
    }
}

fn parse_cpu_line(rest: &str) -> CpuTimes {
    let mut it = rest.split_ascii_whitespace().map(|t| t.parse::<u64>().unwrap_or(0));
    // Older kernels emit fewer columns; a missing column reads as 0.
    CpuTimes {
        user: it.next().unwrap_or(0),
        nice: it.next().unwrap_or(0),
        system: it.next().unwrap_or(0),
        idle: it.next().unwrap_or(0),
        iowait: it.next().unwrap_or(0),
        irq: it.next().unwrap_or(0),
        softirq: it.next().unwrap_or(0),
        steal: it.next().unwrap_or(0),
        guest: it.next().unwrap_or(0),
        guest_nice: it.next().unwrap_or(0),
    }
}

#[derive(Debug, Clone, Default)]
pub struct StatFile {
    pub total: CpuTimes,
    pub per_cpu: Vec<CpuTimes>,
    /// Context switches since boot; a useful secondary signal.
    pub ctxt: u64,
    pub procs_running: u64,
    pub procs_blocked: u64,
}

pub fn parse_proc_stat(s: &str) -> StatFile {
    let mut out = StatFile::default();
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("cpu") {
            match rest.chars().next() {
                Some(c) if c.is_ascii_whitespace() => out.total = parse_cpu_line(rest),
                Some(c) if c.is_ascii_digit() => {
                    // "cpu0 1 2 3" -> skip the index, keep the numbers.
                    let after = rest.trim_start_matches(|c: char| c.is_ascii_digit());
                    out.per_cpu.push(parse_cpu_line(after));
                }
                _ => {}
            }
        } else if let Some(v) = line.strip_prefix("ctxt ") {
            out.ctxt = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("procs_running ") {
            out.procs_running = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("procs_blocked ") {
            out.procs_blocked = v.trim().parse().unwrap_or(0);
        }
    }
    out
}

// ------------------------------------------------------- /proc/[pid]/stat --

/// Identity of a process. A bare PID is NOT an identity: Linux recycles PIDs,
/// and on a busy machine with a low `pid_max` it can happen within seconds.
///
/// `starttime` (field 22 of /proc/[pid]/stat) is the boot-relative time the
/// process began, in clock ticks. It never changes for a live process and a
/// recycled PID will practically always have a different one. Keying on the
/// pair means a new process inheriting an old PID is treated as new, rather
/// than having a nonsensical CPU delta computed against its predecessor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcKey {
    pub pid: i32,
    pub starttime: u64,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PidStat {
    pub pid: i32,
    pub comm: String,
    pub state: char,
    pub ppid: i32,
    pub utime: u64,
    pub stime: u64,
    pub num_threads: i64,
    pub starttime: u64,
    pub vsize: u64,
    /// Resident set, in PAGES. Multiply by page size for bytes.
    pub rss_pages: i64,
}

impl PidStat {
    pub fn key(&self) -> ProcKey {
        ProcKey { pid: self.pid, starttime: self.starttime }
    }
    pub fn rss_bytes(&self) -> u64 {
        if self.rss_pages <= 0 {
            0
        } else {
            self.rss_pages as u64 * sys_const().page_size
        }
    }
    pub fn cpu_ticks(&self) -> u64 {
        self.utime + self.stime
    }
}

/// Parse `/proc/[pid]/stat`.
///
/// The layout is `pid (comm) state ppid ...`, and `comm` is the single field
/// that cannot be located by splitting on whitespace: the kernel copies up to 16
/// bytes of the executable name in verbatim, so it may contain spaces AND
/// parentheses. A process named `weird ) name (x` is entirely legal.
///
/// The only correct approach is to locate the FIRST `(` and the LAST `)` and
/// treat everything between them as the name. Everything after the last `)` is
/// fixed-width and splits on whitespace safely.
pub fn parse_pid_stat(s: &str) -> Option<PidStat> {
    let open = s.find('(')?;
    let close = s.rfind(')')?;
    if close < open {
        return None;
    }
    let pid: i32 = s[..open].trim().parse().ok()?;
    let comm = s[open + 1..close].to_string();

    let rest: Vec<&str> = s[close + 1..].split_ascii_whitespace().collect();
    // Index i here is field number i+3 in proc(5)'s 1-based numbering.
    let get = |i: usize| -> Option<&str> { rest.get(i).copied() };

    Some(PidStat {
        pid,
        comm,
        state: get(0)?.chars().next()?,
        ppid: get(1)?.parse().ok()?,
        utime: get(11)?.parse().ok()?,      // field 14
        stime: get(12)?.parse().ok()?,      // field 15
        num_threads: get(17)?.parse().ok()?, // field 20
        starttime: get(19)?.parse().ok()?,   // field 22
        vsize: get(20)?.parse().ok()?,       // field 23
        rss_pages: get(21)?.parse().ok()?,   // field 24
    })
}

// --------------------------------------------------------- /proc/[pid]/io --

/// Cumulative I/O counters for one process.
///
/// `read_bytes`/`write_bytes` are what actually went to or from the block layer.
/// `rchar`/`wchar` count bytes passed to read()/write() syscalls, which includes
/// data served from page cache and data that never reaches a disk at all (pipes,
/// sockets, /dev/null). Reporting rchar as "disk read" is a common and
/// misleading bug; we keep both and label them distinctly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PidIo {
    pub rchar: u64,
    pub wchar: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
}

pub fn parse_pid_io(s: &str) -> PidIo {
    let mut io = PidIo::default();
    for line in s.lines() {
        let mut it = line.splitn(2, ':');
        let (k, v) = match (it.next(), it.next()) {
            (Some(k), Some(v)) => (k.trim(), v.trim()),
            _ => continue,
        };
        let n = v.parse::<u64>().unwrap_or(0);
        match k {
            "rchar" => io.rchar = n,
            "wchar" => io.wchar = n,
            "read_bytes" => io.read_bytes = n,
            "write_bytes" => io.write_bytes = n,
            _ => {}
        }
    }
    io
}

// ----------------------------------------------------------- /proc/meminfo --

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemInfo {
    pub total: u64,
    pub free: u64,
    pub available: u64,
    pub buffers: u64,
    pub cached: u64,
    pub swap_total: u64,
    pub swap_free: u64,
}

impl MemInfo {
    /// Used memory, defined as total minus MemAvailable.
    ///
    /// Not `total - free`: that counts page cache as used and makes a healthy
    /// Linux box look permanently out of memory. MemAvailable is the kernel's
    /// own estimate of what a new allocation could obtain without swapping, and
    /// it is the honest number to alert on.
    pub fn used(&self) -> u64 {
        self.total.saturating_sub(self.available)
    }
    pub fn used_pct(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.used() as f64 / self.total as f64 * 100.0
        }
    }
}

pub fn parse_meminfo(s: &str) -> MemInfo {
    let mut m = MemInfo::default();
    for line in s.lines() {
        let mut it = line.splitn(2, ':');
        let (k, v) = match (it.next(), it.next()) {
            (Some(k), Some(v)) => (k.trim(), v.trim()),
            _ => continue,
        };
        // Values are "12345 kB". Fields are in kibibytes, not bytes.
        let kb = v
            .split_ascii_whitespace()
            .next()
            .and_then(|n| n.parse::<u64>().ok())
            .unwrap_or(0);
        let bytes = kb.saturating_mul(1024);
        match k {
            "MemTotal" => m.total = bytes,
            "MemFree" => m.free = bytes,
            "MemAvailable" => m.available = bytes,
            "Buffers" => m.buffers = bytes,
            "Cached" => m.cached = bytes,
            "SwapTotal" => m.swap_total = bytes,
            "SwapFree" => m.swap_free = bytes,
            _ => {}
        }
    }
    // Very old kernels (<3.14) have no MemAvailable; approximate it.
    if m.available == 0 && m.total > 0 {
        m.available = m.free + m.buffers + m.cached;
    }
    m
}

// ---------------------------------------------------------- /proc/net/dev --

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetDev {
    pub name: String,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub rx_errs: u64,
    pub rx_drop: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub tx_errs: u64,
    pub tx_drop: u64,
}

/// Parse `/proc/net/dev`. Two header lines, then `iface: <16 counters>`.
/// The interface name is followed by a colon that may or may not have a space
/// after it, and on a busy interface the first counter can run right up against
/// the colon, so splitting on ':' first is required.
pub fn parse_net_dev(s: &str) -> Vec<NetDev> {
    let mut out = Vec::new();
    for line in s.lines().skip(2) {
        let (name, rest) = match line.split_once(':') {
            Some((a, b)) => (a.trim(), b),
            None => continue,
        };
        let f: Vec<u64> = rest
            .split_ascii_whitespace()
            .map(|t| t.parse::<u64>().unwrap_or(0))
            .collect();
        if f.len() < 16 {
            continue;
        }
        out.push(NetDev {
            name: name.to_string(),
            rx_bytes: f[0],
            rx_packets: f[1],
            rx_errs: f[2],
            rx_drop: f[3],
            tx_bytes: f[8],
            tx_packets: f[9],
            tx_errs: f[10],
            tx_drop: f[11],
        });
    }
    out
}

// ---------------------------------------------------------- /proc/net/tcp --

/// A socket's inode number, used to attribute sockets to processes.
///
/// There is no per-process byte counter for the network anywhere in /proc. What
/// /proc does expose is a socket table with inode numbers, and each process's
/// /proc/[pid]/fd contains symlinks of the form `socket:[12345]`. Joining the
/// two gives you which process owns which connection — not how many bytes it
/// moved. See docs/DESIGN.md for why byte-level attribution needs eBPF.
pub fn parse_net_tcp_inodes(s: &str) -> Vec<u64> {
    let mut out = Vec::new();
    for line in s.lines().skip(1) {
        let f: Vec<&str> = line.split_ascii_whitespace().collect();
        // sl local rem st tx:rx tr:when retrnsmt uid timeout inode
        if f.len() > 9 {
            if let Ok(ino) = f[9].parse::<u64>() {
                if ino != 0 {
                    out.push(ino);
                }
            }
        }
    }
    out
}

/// Extract the inode from an fd symlink target like `socket:[12345]`.
pub fn socket_inode_from_link(target: &str) -> Option<u64> {
    target.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
}
