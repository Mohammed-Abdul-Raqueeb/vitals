//! Collector tests against a fabricated procfs tree.
//!
//! Unlike tests/parsers.rs, these exercise the real filesystem-reading path in
//! sample.rs — directory listing, permission handling, and the process
//! genuinely vanishing between listing and reading. A fake /proc directory
//! makes both reproducible: a real /proc changes under us every millisecond,
//! which would make an assertion like "exactly 2 processes" flaky by nature.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use vitals::sample::Collector;

fn fixture_root() -> PathBuf {
    let d = std::env::temp_dir().join(format!("vitals-fixture-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// Write a minimal but realistic set of /proc files for `pid`.
fn write_proc_entry(root: &Path, pid: i32, comm: &str, utime: u64, rss_pages: i64) {
    let dir = root.join(pid.to_string());
    fs::create_dir_all(&dir).unwrap();
    // pid (comm) state ppid ... 20 fields ... utime stime ... starttime vsize rss ...
    let stat = format!(
        "{pid} ({comm}) R 1 {pid} {pid} 0 -1 4194304 0 0 0 0 {utime} 0 0 0 20 0 1 0 {start} 1000 {rss} 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
        pid = pid, comm = comm, utime = utime, start = 100 + pid as u64, rss = rss_pages,
    );
    fs::write(dir.join("stat"), stat).unwrap();
    fs::write(
        dir.join("io"),
        "rchar: 100\nwchar: 0\nsyscr: 1\nsyscw: 0\nread_bytes: 0\nwrite_bytes: 0\ncancelled_write_bytes: 0\n",
    )
    .unwrap();
}

fn write_system_files(root: &Path) {
    fs::write(
        root.join("stat"),
        "cpu  100 0 50 800 10 0 0 0 0 0\ncpu0 100 0 50 800 10 0 0 0 0 0\nctxt 1000\nprocs_running 1\nprocs_blocked 0\n",
    )
    .unwrap();
    fs::write(
        root.join("meminfo"),
        "MemTotal: 2000 kB\nMemFree: 500 kB\nMemAvailable: 1200 kB\nBuffers: 0 kB\nCached: 0 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",
    )
    .unwrap();
    fs::create_dir_all(root.join("net")).unwrap();
    fs::write(
        root.join("net/dev"),
        "Inter-|Receive|Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n  eth0: 1000 10 0 0 0 0 0 0  2000 20 0 0 0 0 0 0\n",
    )
    .unwrap();
    // A non-numeric entry, which a naive `parse::<i32>` over all dir entries
    // would choke on if not filtered.
    fs::create_dir_all(root.join("self")).unwrap();
    fs::create_dir_all(root.join("sys")).unwrap();
}

#[test]
fn collector_reads_a_fabricated_proc_tree_and_skips_non_pid_entries() {
    let root = fixture_root();
    write_system_files(&root);
    write_proc_entry(&root, 100, "alpha", 500, 20);
    write_proc_entry(&root, 200, "beta", 0, 5);

    let c = Collector::new(&root);
    let s = c.collect().expect("collect should succeed on a well-formed tree");

    assert_eq!(s.procs.len(), 2, "self/ and sys/ must not be mistaken for pids");
    assert_eq!(s.vanished, 0);
    assert_eq!(s.mem.total, 2000 * 1024);
    assert_eq!(s.nets.len(), 1);
    assert_eq!(s.nets[0].name, "eth0");

    let names: Vec<&str> = {
        let mut v: Vec<&str> = s.procs.values().map(|p| p.stat.comm.as_str()).collect();
        v.sort();
        v
    };
    assert_eq!(names, vec!["alpha", "beta"]);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_process_directory_that_disappears_mid_scan_is_counted_not_fatal() {
    // This is the real "process dies mid-sample" scenario, exercised against
    // the actual filesystem-reading code path rather than simulated in a unit
    // test of the parser. We list the directory (which includes pid 999), then
    // delete pid 999 before the collector gets to read its stat file, by
    // racing a background thread against the collector's own scan.
    let root = fixture_root();
    write_system_files(&root);
    write_proc_entry(&root, 100, "steady", 10, 5);
    write_proc_entry(&root, 999, "ephemeral", 10, 5);

    // Bias the race toward hitting the window: give the collector a head start
    // on 100 numeric-looking sibling directories, so by the time it reaches 999
    // the deleter thread has had time to run. This does not change program
    // behaviour, only the odds the test observes the interesting path in a
    // single run; the assertions below hold regardless of which path is hit.
    for pid in 300..320 {
        write_proc_entry(&root, pid, "filler", 1, 1);
    }

    let root2 = root.clone();
    let deleter = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_micros(200));
        let _ = fs::remove_dir_all(root2.join("999"));
    });

    let c = Collector::new(&root);
    let s = c.collect().expect("a vanished process must not fail the whole scan");
    deleter.join().unwrap();

    // Whichever way the race went, pid 100 must always be present and the scan
    // must always succeed. If we won the race, 999 is counted as vanished
    // rather than crashing the collector.
    assert!(s.procs.values().any(|p| p.stat.comm == "steady"));
    assert!(
        s.procs.values().any(|p| p.stat.comm == "ephemeral") || s.vanished >= 1,
        "pid 999 must be either read successfully or counted as vanished, never silently lost"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn unreadable_io_file_is_reported_as_denied_not_zero() {
    let root = fixture_root();
    write_system_files(&root);
    write_proc_entry(&root, 100, "locked", 10, 5);

    // Simulate EACCES on /proc/[pid]/io, which is the normal case for a
    // process owned by a different user.
    let io_path = root.join("100/io");
    fs::set_permissions(&io_path, fs::Permissions::from_mode(0o000)).unwrap();

    let c = Collector::new(&root);
    let s = c.collect().expect("permission errors on io must not fail the scan");

    // Restore permissions before cleanup, or the temp dir may not delete.
    fs::set_permissions(&io_path, fs::Permissions::from_mode(0o644)).unwrap();

    // Running as root in this container, an unreadable-by-permissions file may
    // still be readable, so only assert the shape: if denied, io is None and
    // counted; if root bypassed the permission bit, io is Some. Either is
    // consistent, but the two must never disagree.
    let p = s.procs.values().find(|p| p.stat.comm == "locked").unwrap();
    if p.io.is_none() {
        assert_eq!(s.io_denied, 1, "a None io must be counted as denied");
    } else {
        assert_eq!(s.io_denied, 0);
    }

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn scan_time_is_measured_and_nonzero_for_a_nonempty_tree() {
    let root = fixture_root();
    write_system_files(&root);
    for pid in 100..150 {
        write_proc_entry(&root, pid, "worker", 1, 1);
    }
    let c = Collector::new(&root);
    let s = c.collect().unwrap();
    assert_eq!(s.procs.len(), 50);
    // Not a strict bound (machines vary), just proof the timer is wired up.
    assert!(s.scan_time.as_nanos() > 0);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn socket_counting_reads_fd_symlinks_when_enabled() {
    let root = fixture_root();
    write_system_files(&root);
    write_proc_entry(&root, 100, "netty", 5, 5);
    let fd_dir = root.join("100/fd");
    fs::create_dir_all(&fd_dir).unwrap();
    std::os::unix::fs::symlink("socket:[555]", fd_dir.join("3")).unwrap();
    std::os::unix::fs::symlink("socket:[556]", fd_dir.join("4")).unwrap();
    std::os::unix::fs::symlink("/dev/null", fd_dir.join("5")).unwrap();

    let mut c = Collector::new(&root);
    c.with_sockets = true;
    let s = c.collect().unwrap();
    let p = s.procs.values().find(|p| p.stat.comm == "netty").unwrap();
    assert_eq!(p.sockets, Some(2), "only socket: links should be counted");

    let mut c2 = Collector::new(&root);
    c2.with_sockets = false;
    let s2 = c2.collect().unwrap();
    let p2 = s2.procs.values().find(|p| p.stat.comm == "netty").unwrap();
    assert_eq!(p2.sockets, None, "socket counting must be opt-in given its cost");

    let _ = fs::remove_dir_all(&root);
}
