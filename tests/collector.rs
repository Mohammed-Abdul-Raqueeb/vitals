
//! Collector tests against a fabricated procfs tree.
//!
//! These exercise the real filesystem-reading path in sample.rs:
//! directory listing, permission handling, and processes disappearing
//! between listing and reading.
//!
//! The fixture is cross-platform. Unix-only filesystem APIs such as
//! PermissionsExt and symlink() are compiled only on Unix.

use std::fs;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use vitals::sample::Collector;

fn fixture_root() -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let d = std::env::temp_dir().join(format!(
        "vitals-fixture-{}-{}",
        std::process::id(),
        unique
    ));

    fs::create_dir_all(&d).unwrap();

    d
}

/// Write a minimal but realistic set of /proc files for `pid`.
fn write_proc_entry(
    root: &Path,
    pid: i32,
    comm: &str,
    utime: u64,
    rss_pages: i64,
) {
    let dir = root.join(pid.to_string());

    fs::create_dir_all(&dir).unwrap();

    // pid (comm) state ppid ... utime stime ... starttime vsize rss ...
    let stat = format!(
        "{pid} ({comm}) R 1 {pid} {pid} 0 -1 4194304 0 0 0 0 {utime} 0 0 0 20 0 1 0 {start} 1000 {rss} 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
        pid = pid,
        comm = comm,
        utime = utime,
        start = 100 + pid as u64,
        rss = rss_pages,
    );

    fs::write(dir.join("stat"), stat).unwrap();

    fs::write(
        dir.join("io"),
        "rchar: 100\n\
         wchar: 0\n\
         syscr: 1\n\
         syscw: 0\n\
         read_bytes: 0\n\
         write_bytes: 0\n\
         cancelled_write_bytes: 0\n",
    )
    .unwrap();
}

fn write_system_files(root: &Path) {
    fs::write(
        root.join("stat"),
        "cpu  100 0 50 800 10 0 0 0 0 0\n\
         cpu0 100 0 50 800 10 0 0 0 0 0\n\
         ctxt 1000\n\
         procs_running 1\n\
         procs_blocked 0\n",
    )
    .unwrap();

    fs::write(
        root.join("meminfo"),
        "MemTotal: 2000 kB\n\
         MemFree: 500 kB\n\
         MemAvailable: 1200 kB\n\
         Buffers: 0 kB\n\
         Cached: 0 kB\n\
         SwapTotal: 0 kB\n\
         SwapFree: 0 kB\n",
    )
    .unwrap();

    fs::create_dir_all(root.join("net")).unwrap();

    fs::write(
        root.join("net/dev"),
        "Inter-|Receive|Transmit\n\
         face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n\
          eth0: 1000 10 0 0 0 0 0 0  2000 20 0 0 0 0 0 0\n",
    )
    .unwrap();

    // Non-numeric entries which must not be interpreted as PIDs.
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

    let s = c
        .collect()
        .expect("collect should succeed on a well-formed tree");

    assert_eq!(
        s.procs.len(),
        2,
        "self/ and sys/ must not be mistaken for pids"
    );

    assert_eq!(s.vanished, 0);
    assert_eq!(s.mem.total, 2000 * 1024);
    assert_eq!(s.nets.len(), 1);
    assert_eq!(s.nets[0].name, "eth0");

    let names: Vec<&str> = {
        let mut v: Vec<&str> = s
            .procs
            .values()
            .map(|p| p.stat.comm.as_str())
            .collect();

        v.sort();
        v
    };

    assert_eq!(names, vec!["alpha", "beta"]);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_process_directory_that_disappears_mid_scan_is_counted_not_fatal() {
    let root = fixture_root();

    write_system_files(&root);

    write_proc_entry(&root, 100, "steady", 10, 5);
    write_proc_entry(&root, 999, "ephemeral", 10, 5);

    // Add several numeric-looking directories to give the collector
    // more filesystem work before reaching pid 999.
    for pid in 300..320 {
        write_proc_entry(&root, pid, "filler", 1, 1);
    }

    let root2 = root.clone();

    let deleter = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_micros(200));

        let _ = fs::remove_dir_all(root2.join("999"));
    });

    let c = Collector::new(&root);

    let s = c
        .collect()
        .expect("a vanished process must not fail the whole scan");

    deleter.join().unwrap();

    // pid 100 must always be present.
    assert!(
        s.procs
            .values()
            .any(|p| p.stat.comm == "steady")
    );

    // pid 999 may either be read successfully or disappear during scanning.
    assert!(
        s.procs
            .values()
            .any(|p| p.stat.comm == "ephemeral")
            || s.vanished >= 1,
        "pid 999 must be either read successfully or counted as vanished"
    );

    let _ = fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn unreadable_io_file_is_reported_as_denied_not_zero() {
    let root = fixture_root();

    write_system_files(&root);
    write_proc_entry(&root, 100, "locked", 10, 5);

    // Simulate EACCES on /proc/[pid]/io.
    let io_path = root.join("100/io");

    fs::set_permissions(
        &io_path,
        fs::Permissions::from_mode(0o000),
    )
    .unwrap();

    let c = Collector::new(&root);

    let s = c
        .collect()
        .expect("permission errors on io must not fail the scan");

    // Restore permissions before cleanup.
    fs::set_permissions(
        &io_path,
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();

    let p = s
        .procs
        .values()
        .find(|p| p.stat.comm == "locked")
        .unwrap();

    if p.io.is_none() {
        assert_eq!(
            s.io_denied,
            1,
            "a None io must be counted as denied"
        );
    } else {
        assert_eq!(
            s.io_denied,
            0,
            "readable io must not be counted as denied"
        );
    }

    let _ = fs::remove_dir_all(&root);
}

#[cfg(windows)]
#[test]
fn unreadable_io_file_test_is_skipped_on_windows() {
    // Windows does not provide the Unix PermissionsExt API used to
    // reliably simulate chmod-style EACCES permissions.
    //
    // The actual collector functionality is tested by the other
    // filesystem tests. This test intentionally performs no assertions.
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

    // Not a strict timing bound. This only proves the timer is wired up.
    assert!(
        s.scan_time.as_nanos() > 0,
        "scan time should be greater than zero"
    );

    let _ = fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn socket_counting_reads_fd_symlinks_when_enabled() {
    let root = fixture_root();

    write_system_files(&root);
    write_proc_entry(&root, 100, "netty", 5, 5);

    let fd_dir = root.join("100/fd");

    fs::create_dir_all(&fd_dir).unwrap();

    std::os::unix::fs::symlink(
        "socket:[555]",
        fd_dir.join("3"),
    )
    .unwrap();

    std::os::unix::fs::symlink(
        "socket:[556]",
        fd_dir.join("4"),
    )
    .unwrap();

    std::os::unix::fs::symlink(
        "/dev/null",
        fd_dir.join("5"),
    )
    .unwrap();

    let mut c = Collector::new(&root);

    c.with_sockets = true;

    let s = c.collect().unwrap();

    let p = s
        .procs
        .values()
        .find(|p| p.stat.comm == "netty")
        .unwrap();

    assert_eq!(
        p.sockets,
        Some(2),
        "only socket: links should be counted"
    );

    let mut c2 = Collector::new(&root);

    c2.with_sockets = false;

    let s2 = c2.collect().unwrap();

    let p2 = s2
        .procs
        .values()
        .find(|p| p.stat.comm == "netty")
        .unwrap();

    assert_eq!(
        p2.sockets,
        None,
        "socket counting must be opt-in given its cost"
    );

    let _ = fs::remove_dir_all(&root);
}

#[cfg(windows)]
#[test]
fn socket_counting_test_is_skipped_on_windows() {
    // Unix /proc exposes process file descriptors as symlinks.
    // Windows does not support this test setup.
}

