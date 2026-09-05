# Design decisions & interview defense

## 1. Why USER_HZ/page size from `/proc/self/auxv`, not libc
`sysconf(_SC_CLK_TCK)` is the normal way, but it needs libc. The kernel already
hands every process these values in its auxiliary vector at exec time
(`AT_CLKTCK=17`, `AT_PAGESZ=6`). Reading it keeps the crate on stdlib alone,
and it's *more* correct than hardcoding 100/4096 — CONFIG_HZ can be 250/300/1000,
and page size is 16KiB on some arm64 kernels.

## 2. `comm` parsing: first `(` , LAST `)`
`/proc/[pid]/stat` is `pid (comm) state ...`. The kernel copies the executable
name verbatim into `comm` — it can legally contain spaces AND parentheses
(`a b) c (d`). Splitting on whitespace, or matching the first `)`, silently
misparses every field after it. Tested in `pid_stat_field_offsets_match_a_real_sample`
and `comm_containing_spaces_and_parens_is_parsed_correctly`.

## 3. PID recycling: key on `(pid, starttime)`, not pid alone
Linux recycles PIDs, sometimes within seconds under a low `pid_max`. `starttime`
(field 22, boot-relative ticks) never changes for a live process and is
effectively unique per (pid, boot). Keying on the pair means a recycled PID is
correctly treated as a brand-new process — no delta computed against a
predecessor. Without this: `recycled_pid_is_treated_as_a_new_process_not_a_huge_delta`
shows the alternative is either an 18-quintillion-byte/s spike (unsigned
underflow) or a negative delta.

## 4. CPU% normalization: per-core ratio vs "one core = 100%"
Per-process: `pct = delta_ticks / (USER_HZ * elapsed_secs) * 100` — top's
convention, so an 8-threaded process on 8 cores can read 800%. Alternative
(dividing by total `/proc/stat` ticks) requires both files sampled at the exact
same instant, which never holds once a per-process scan takes milliseconds.
System-wide CPU uses the `/proc/stat` ratio instead, because there numerator
and denominator come from the same read and are consistent by construction.

`guest`/`guest_nice` are excluded from `total()` — the kernel already counts
them inside `user`/`nice`, so adding them again inflates the denominator and
makes every percentage read low on a VM host. `busy()` excludes `iowait` too:
the CPU was available, just idle waiting on disk.

## 5. Memory: `used = total - MemAvailable`, not `total - free`
`total - free` counts page cache as "used" and makes a healthy Linux box look
permanently out of memory. `MemAvailable` is the kernel's own estimate of what
a new allocation could get without swapping — the honest number to alert on.
Falls back to `free + buffers + cached` on kernels <3.14 that lack the field.

## 6. Ring buffer: fixed array, not `VecDeque`
A `VecDeque` grows past capacity unless every caller remembers to pop first —
the bound depends on discipline. A `Vec<Option<T>>` of exactly `capacity` slots
with a write cursor makes overwrite-oldest the *only* behavior possible; push is
O(1), no reallocation, no memmove. Cost: one `Option` discriminant per slot,
negligible next to the guarantee.

## 7. Alert engine: sustain + hysteresis, and why both
A bare threshold flaps: a value oscillating 78%/82% around an 80% threshold
fires and clears every tick. Two independent mechanisms fix different halves:
- **`for <duration>` (sustain)** — suppresses transients; a one-sample spike
  never fires.
- **`clear <value>` (hysteresis / deadband)** — fires above threshold, only
  clears below a lower value. `without_hysteresis_the_same_wobble_flaps` proves
  the flap is real without it; `hysteresis_prevents_flapping_around_the_threshold`
  proves one deadband fixes it (1 Fired, 0 Cleared across 8 oscillating samples).

A firing alert whose process exits **clears immediately** (`ClearedGone`) rather
than latching forever on a dead PID — reaped in the same tick it disappears
from the scan.

## 8. Sampler thread: lock held only for handover
Spawning a background thread isn't sufficient by itself — if it holds the lock
during file I/O, a reader stalls for the full scan anyway. Ordering is:
collect() → diff() → engine.evaluate() all happen with **no lock held**; the
write lock wraps only the final pointer swap. Proven empirically (not just
argued) in `tests/no_ui_block.rs` against a synthetic 3000-process `/proc`:
scans take ~50ms, but a reader hammering the lock throughout sees a worst case
of 8.5ms and an average of 81ns — nowhere near converging on scan time, which
is what would happen if the lock were held across I/O.

Interval is drift-corrected: `sleep(interval - work_time)` instead of
`work(); sleep(interval)`, so sample rate doesn't silently degrade under load.
If a scan overruns the interval, the next scan is *not* queued immediately —
we skip the sleep and record an overrun rather than making the monitor add to
the load it's reporting on.

## 9. Why sockets give ownership, not byte-level attribution
`/proc/net/tcp` has a socket table with inode numbers; `/proc/[pid]/fd/*` are
symlinks `socket:[12345]`. Joining the two tells you *which process owns which
connection* — not how many bytes it moved. There is no per-process network byte
counter anywhere in `/proc`. Real per-process network attribution needs eBPF
(cgroup or socket-filter programs) or per-process network namespaces; both are
out of scope for a project explicitly built against `/proc`. `--sockets` is
off by default because a full `fd` readdir per process is by far the most
expensive part of a scan — it's a design tradeoff stated up front, not hidden.

## 10. Not built, and why
- **GUI**: intended as Tauri (Rust core unchanged, web UI calling in via
  commands) but not built — this sandbox has no `webkit2gtk`/Node. The
  integration points already exist: `Snapshot`/`SamplerHandle` are the exact
  data a progress view would consume.
- **Interactive TUI** (sort keys, kill from the UI): needs raw terminal mode
  (termios), which needs libc. Left out to keep the zero-dependency property;
  the redraw-in-place approach also avoids needing a SIGINT handler to restore
  an alternate screen buffer.
