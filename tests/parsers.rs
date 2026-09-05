//! Parser tests.
//!
//! Every awkward case in procfs parsing is about file *content*, so these are
//! written as string literals against the pure parsers. No filesystem needed.

use vitals::procfs::*;
use vitals::units::{count_cpus, human_bytes, parse_duration, parse_size};

/// A real line captured from this machine, used as the ground truth for field
/// offsets. Getting the indices wrong is silent — you get plausible numbers
/// from the wrong columns — so this is pinned against a known-good sample.
const REAL_STAT: &str = "473 (cat) R 472 472 0 0 -1 4194304 61 0 1 0 0 0 0 0 20 0 1 0 2302 2916352 367 18446744073709551615 94274036805632 94274036823217 140722590927472 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 94274036837008 94274036838504 94274964389888 140722590932271 140722590932291 140722590932291 140722590932971 0";

#[test]
fn pid_stat_field_offsets_match_a_real_sample() {
    let s = parse_pid_stat(REAL_STAT).expect("should parse");
    assert_eq!(s.pid, 473);
    assert_eq!(s.comm, "cat");
    assert_eq!(s.state, 'R');
    assert_eq!(s.ppid, 472);
    assert_eq!(s.utime, 0);
    assert_eq!(s.stime, 0);
    assert_eq!(s.num_threads, 1);
    assert_eq!(s.starttime, 2302);
    assert_eq!(s.vsize, 2916352);
    assert_eq!(s.rss_pages, 367);
}

#[test]
fn comm_containing_spaces_and_parens_is_parsed_correctly() {
    // The kernel copies up to 16 bytes of the executable name into `comm`
    // verbatim. Spaces and parentheses are legal and DO occur in the wild
    // (JVM threads, anything renamed via prctl). Splitting on whitespace, or
    // scanning for the FIRST ')', gives garbage for these.
    let cases = [
        ("7 (my prog) S 1", "my prog", 'S'),
        ("7 (weird)name) S 1", "weird)name", 'S'),
        ("7 ((paren)) R 1", "(paren)", 'R'),
        ("7 (a b) c (d) Z 1", "a b) c (d", 'Z'),
        ("7 () S 1", "", 'S'),
    ];
    for (line, want_comm, want_state) in cases {
        // Pad out the trailing fields so parsing reaches field 24.
        let padded = format!("{}{}", line, " 0".repeat(30));
        let s = parse_pid_stat(&padded)
            .unwrap_or_else(|| panic!("failed to parse: {}", line));
        assert_eq!(s.comm, want_comm, "comm wrong for {:?}", line);
        assert_eq!(s.state, want_state, "state wrong for {:?}", line);
        assert_eq!(s.pid, 7);
    }
}

#[test]
fn malformed_pid_stat_returns_none_rather_than_panicking() {
    // A monitor must never crash on a weird line; it skips and carries on.
    for bad in ["", "no parens here", "12 (unclosed", "12 )backwards( S 1", "(x) S 1"] {
        assert!(parse_pid_stat(bad).is_none(), "should have rejected: {:?}", bad);
    }
    // Well-formed prefix but truncated before the fields we need.
    assert!(parse_pid_stat("12 (ok) S 1 2 3").is_none());
}

#[test]
fn cpu_total_excludes_guest_to_avoid_double_counting() {
    // guest is already included in user, guest_nice in nice. Adding them again
    // inflates the denominator and makes every CPU percentage read low.
    let line = "cpu  100 20 30 1000 5 1 2 3 40 10\n";
    let st = parse_proc_stat(line);
    let c = st.total;
    assert_eq!(c.user, 100);
    assert_eq!(c.guest, 40);
    assert_eq!(c.guest_nice, 10);
    // 100+20+30+1000+5+1+2+3 = 1161, with guest/guest_nice excluded.
    assert_eq!(c.total(), 1161);
    // busy excludes idle AND iowait: 1161 - 1000 - 5 = 156.
    assert_eq!(c.busy(), 156);
}

#[test]
fn proc_stat_separates_aggregate_from_per_core() {
    let s = "cpu  1 2 3 4 5 6 7 8 0 0
cpu0 1 1 1 1 1 1 1 1 0 0
cpu1 2 2 2 2 2 2 2 2 0 0
intr 5 0 0
ctxt 987654
procs_running 3
procs_blocked 1
";
    let st = parse_proc_stat(s);
    assert_eq!(st.per_cpu.len(), 2, "cpu0/cpu1 counted, aggregate excluded");
    assert_eq!(st.total.user, 1);
    assert_eq!(st.per_cpu[1].user, 2);
    assert_eq!(st.ctxt, 987654);
    assert_eq!(st.procs_running, 3);
    assert_eq!(st.procs_blocked, 1);
    assert_eq!(count_cpus(s), 2);
}

#[test]
fn meminfo_used_is_based_on_available_not_free() {
    // total - free would count page cache as used and make every healthy Linux
    // box look like it is out of memory.
    let s = "MemTotal:       1000 kB
MemFree:          50 kB
MemAvailable:    600 kB
Buffers:          20 kB
Cached:          500 kB
SwapTotal:       200 kB
SwapFree:        200 kB
";
    let m = parse_meminfo(s);
    assert_eq!(m.total, 1000 * 1024);
    assert_eq!(m.available, 600 * 1024);
    assert_eq!(m.used(), 400 * 1024, "used = total - available");
    assert!((m.used_pct() - 40.0).abs() < 1e-9);
}

#[test]
fn meminfo_falls_back_when_memavailable_is_absent() {
    // Kernels older than 3.14 have no MemAvailable field.
    let s = "MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 50 kB\nCached: 200 kB\n";
    let m = parse_meminfo(s);
    assert_eq!(m.available, 350 * 1024, "free + buffers + cached");
}

#[test]
fn net_dev_handles_counters_butted_against_the_colon() {
    // On a busy interface the first counter runs right up against the colon
    // with no space: "eth0:1234567890 42 ...". Splitting on whitespace first
    // would merge the name and the byte count into one token.
    let s = "Inter-|   Receive                        |  Transmit
 face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed
    lo:  100 1 0 0 0 0 0 0  100 1 0 0 0 0 0 0
  eth0:99999 60 1 2 0 0 0 0  15741 56 3 4 0 0 0 0
";
    let d = parse_net_dev(s);
    assert_eq!(d.len(), 2);
    assert_eq!(d[0].name, "lo");
    assert_eq!(d[1].name, "eth0");
    assert_eq!(d[1].rx_bytes, 99999, "counter jammed against the colon");
    assert_eq!(d[1].rx_packets, 60);
    assert_eq!(d[1].rx_errs, 1);
    assert_eq!(d[1].rx_drop, 2);
    assert_eq!(d[1].tx_bytes, 15741);
    assert_eq!(d[1].tx_errs, 3);
}

#[test]
fn pid_io_distinguishes_syscall_bytes_from_block_layer_bytes() {
    let s = "rchar: 4092\nwchar: 10\nsyscr: 8\nsyscw: 2\nread_bytes: 8192\nwrite_bytes: 4096\ncancelled_write_bytes: 0\n";
    let io = parse_pid_io(s);
    assert_eq!(io.rchar, 4092, "bytes passed to read(), incl. page cache hits");
    assert_eq!(io.read_bytes, 8192, "bytes actually fetched from the block layer");
    assert_eq!(io.write_bytes, 4096);
}

#[test]
fn net_tcp_inode_column_is_located_correctly() {
    let s = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:07E9 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 682 1 00000000cbde3db5 100 0 0 10 0
   1: 00000000:07E8 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 681 1 0000000052a63495 100 0 0 10 0
";
    assert_eq!(parse_net_tcp_inodes(s), vec![682, 681]);
}

#[test]
fn socket_fd_links_are_recognised() {
    assert_eq!(socket_inode_from_link("socket:[12345]"), Some(12345));
    assert_eq!(socket_inode_from_link("/dev/null"), None);
    assert_eq!(socket_inode_from_link("pipe:[999]"), None);
    assert_eq!(socket_inode_from_link("socket:[]"), None);
}

#[test]
fn size_and_duration_parsing() {
    assert_eq!(parse_size("500MB"), Some(500 * 1024 * 1024));
    assert_eq!(parse_size("2G"), Some(2 * 1024 * 1024 * 1024));
    assert_eq!(parse_size("1024"), Some(1024));
    assert_eq!(parse_size("1.5M"), Some(1024 * 1024 + 512 * 1024));
    assert_eq!(parse_size("nope"), None);
    assert_eq!(parse_size("-5M"), None);

    assert_eq!(parse_duration("5s"), Some(std::time::Duration::from_secs(5)));
    assert_eq!(parse_duration("500ms"), Some(std::time::Duration::from_millis(500)));
    assert_eq!(parse_duration("2m"), Some(std::time::Duration::from_secs(120)));
    assert_eq!(parse_duration("30"), Some(std::time::Duration::from_secs(30)));
    assert_eq!(parse_duration("junk"), None);
}

#[test]
fn byte_formatting_is_stable() {
    assert_eq!(human_bytes(0), "0B");
    assert_eq!(human_bytes(1023), "1023B");
    assert_eq!(human_bytes(1024), "1.0K");
    assert_eq!(human_bytes(1024 * 1024), "1.0M");
    assert_eq!(human_bytes(1536 * 1024 * 1024), "1.5G");
}
