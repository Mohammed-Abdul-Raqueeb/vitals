//! Taking one sample of the whole system.
//!
//! `/proc` is a live view, not a snapshot. Three things go wrong if you ignore
//! that, and all three are handled here:
//!
//! 1. **Processes vanish mid-scan.** Between `readdir("/proc")` and
//!    `open("/proc/1234/stat")` the process can exit. Every read is therefore
//!    allowed to fail with NotFound, and such a failure is counted rather than
//!    propagated. A monitor that aborts its scan because a process exited is
//!    useless on exactly the busy machine you wrote it for.
//!
//! 2. **PIDs are recycled.** See `ProcKey` in `procfs.rs`. We key on
//!    (pid, starttime) so a recycled PID never has a delta computed against its
//!    predecessor's counters.
//!
//! 3. **Some files are unreadable.** `/proc/[pid]/io` requires the same UID or
//!    CAP_SYS_PTRACE, so as an unprivileged user most of them return EACCES.
//!    That is normal, not an error: the field becomes `None` and the UI shows a
//!    dash rather than a wrong zero.
//!
//! The collector takes its procfs root as a parameter so tests can point it at a
//! fixture directory instead of the real `/proc`.

use crate::procfs::*;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ProcSample {
    pub stat: PidStat,
    /// None when /proc/[pid]/io is not readable by us.
    pub io: Option<PidIo>,
    /// Open socket count, only populated when socket attribution is enabled.
    pub sockets: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct Sample {
    /// Monotonic instant of the scan start. Monotonic, not wall clock: NTP steps
    /// and DST changes must never be able to produce a negative elapsed time and
    /// therefore a nonsensical rate.
    pub at: Instant,
    pub cpu: StatFile,
    pub mem: MemInfo,
    pub nets: Vec<NetDev>,
    pub procs: HashMap<ProcKey, ProcSample>,
    /// Processes that disappeared between listing and reading. Surfaced rather
    /// than hidden — a high number is a real signal about the machine.
    pub vanished: u32,
    /// Processes whose /proc/[pid]/io we were not permitted to read.
    pub io_denied: u32,
    /// How long this scan took. The monitor measuring its own cost is not
    /// vanity: it is how you know the sampler is not the load it is reporting.
    pub scan_time: Duration,
}

#[derive(Debug, Clone)]
pub struct Collector {
    root: PathBuf,
    /// Attributing sockets to processes means a readdir of /proc/[pid]/fd for
    /// every process, which is by far the most expensive thing in a scan. Off by
    /// default; the cost is measured in docs/DESIGN.md.
    pub with_sockets: bool,
}

impl Default for Collector {
    fn default() -> Self {
        Collector::new("/proc")
    }
}

impl Collector {
    pub fn new<P: Into<PathBuf>>(root: P) -> Self {
        Collector { root: root.into(), with_sockets: false }
    }

    fn read(&self, rel: &str) -> io::Result<String> {
        fs::read_to_string(self.root.join(rel))
    }

    /// Read one file belonging to a process, mapping "it exited" to None.
    fn read_pid(&self, pid: i32, file: &str) -> Result<Option<String>, io::Error> {
        match fs::read_to_string(self.root.join(pid.to_string()).join(file)) {
            Ok(s) => Ok(Some(s)),
            // The process exited between listing and reading. Expected.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            // ESRCH surfaces as Other on some kernels for a dying task.
            Err(e) if e.raw_os_error() == Some(3) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// List numeric entries of the procfs root. Non-numeric entries (`self`,
    /// `net`, `sys`, ...) are skipped, as are thread directories, which do not
    /// appear at this level anyway.
    fn list_pids(&self) -> io::Result<Vec<i32>> {
        let mut pids = Vec::with_capacity(512);
        for entry in fs::read_dir(&self.root)? {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            if let Some(name) = entry.file_name().to_str() {
                if let Ok(pid) = name.parse::<i32>() {
                    pids.push(pid);
                }
            }
        }
        Ok(pids)
    }

    fn count_sockets(&self, pid: i32) -> Option<usize> {
        let dir = self.root.join(pid.to_string()).join("fd");
        let rd = fs::read_dir(dir).ok()?;
        let mut n = 0;
        for e in rd.flatten() {
            if let Ok(target) = fs::read_link(e.path()) {
                if let Some(t) = target.to_str() {
                    if socket_inode_from_link(t).is_some() {
                        n += 1;
                    }
                }
            }
        }
        Some(n)
    }

    pub fn collect(&self) -> io::Result<Sample> {
        let at = Instant::now();

        // System-wide files first, so they are as close in time as possible to
        // each other. Per-process scanning takes far longer and is done after.
        let cpu = parse_proc_stat(&self.read("stat")?);
        let mem = parse_meminfo(&self.read("meminfo")?);
        let nets = self.read("net/dev").map(|s| parse_net_dev(&s)).unwrap_or_default();

        let mut procs = HashMap::with_capacity(512);
        let mut vanished = 0u32;
        let mut io_denied = 0u32;

        for pid in self.list_pids()? {
            let stat_txt = match self.read_pid(pid, "stat")? {
                Some(s) => s,
                None => {
                    vanished += 1;
                    continue;
                }
            };
            let stat = match parse_pid_stat(&stat_txt) {
                Some(s) => s,
                None => continue, // malformed; skip rather than abort the scan
            };

            let io = match fs::read_to_string(
                self.root.join(pid.to_string()).join("io"),
            ) {
                Ok(s) => Some(parse_pid_io(&s)),
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                    io_denied += 1;
                    None
                }
                Err(_) => None,
            };

            let sockets = if self.with_sockets { self.count_sockets(pid) } else { None };

            procs.insert(stat.key(), ProcSample { stat, io, sockets });
        }

        Ok(Sample {
            at,
            cpu,
            mem,
            nets,
            procs,
            vanished,
            io_denied,
            scan_time: at.elapsed(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}
