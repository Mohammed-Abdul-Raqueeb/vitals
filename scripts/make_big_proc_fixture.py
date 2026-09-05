#!/usr/bin/env python3
"""Build a large synthetic /proc tree so a single scan takes long enough to
make the no-UI-block test's timing assertions meaningful.

Usage: python3 scripts/make_big_proc_fixture.py [root] [count]
"""
import os
import sys

root = sys.argv[1] if len(sys.argv) > 1 else "/tmp/bigproc"
count = int(sys.argv[2]) if len(sys.argv) > 2 else 3000

os.makedirs(root, exist_ok=True)
open(os.path.join(root, "stat"), "w").write(
    "cpu  100 0 50 800 10 0 0 0 0 0\nctxt 1000\nprocs_running 1\nprocs_blocked 0\n"
)
open(os.path.join(root, "meminfo"), "w").write(
    "MemTotal: 2000 kB\nMemFree: 500 kB\nMemAvailable: 1200 kB\n"
    "Buffers: 0 kB\nCached: 0 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n"
)
os.makedirs(os.path.join(root, "net"), exist_ok=True)
open(os.path.join(root, "net/dev"), "w").write(
    "Inter-|Receive|Transmit\n"
    " face |bytes packets errs drop fifo frame compressed multicast|"
    "bytes packets errs drop fifo colls carrier compressed\n"
    "  eth0: 1000 10 0 0 0 0 0 0  2000 20 0 0 0 0 0 0\n"
)

for pid in range(100, 100 + count):
    d = os.path.join(root, str(pid))
    os.makedirs(d, exist_ok=True)
    stat = (
        f"{pid} (worker{pid % 7}) R 1 {pid} {pid} 0 -1 4194304 0 0 0 0 5 0 0 0 "
        f"20 0 1 0 {100 + pid} 1000 5 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    )
    open(os.path.join(d, "stat"), "w").write(stat)
    open(os.path.join(d, "io"), "w").write(
        "rchar: 1\nwchar: 0\nsyscr: 1\nsyscw: 0\n"
        "read_bytes: 0\nwrite_bytes: 0\ncancelled_write_bytes: 0\n"
    )

print(f"wrote {count} fake process directories under {root}")
