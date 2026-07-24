# EXP-LL: the race-free successor, benchmarked against the seccomp bypass

Answers the design direction of the paper with a working control. `landlock_gate.c` enforces a
default-deny filesystem-write allowlist via the Landlock LSM (ABI v7 on this host); we run the exact
EXP-11 attack and the syscall-alias probe under both controls. Reproduce: `bash landlock_bench.sh`.

## Benchmark 1 -- the EXP-11 TOCTOU race (N=4000, same target)

| control | evil opened (win) | reading |
|---|---|---|
| seccomp argument-inspection gate | **854 / 4000 (21.4%)** | validates a string, kernel re-reads the pointer -- the race wins |
| Landlock default-deny allowlist | **0 / 4000 (0%)** | in-kernel check on the resolved path; no user-space "check" to invalidate |

The bypass that defeats the seccomp gate ~1-in-5 times is closed completely. Landlock evaluates the
allow decision against the actual file object at the LSM hook, so a sibling thread flipping the path
buffer changes only *which* denied path is attempted, never the decision.

## Benchmark 2 -- syscall-alias coverage (write the persistence path three ways)

| control | open | creat | openat |
|---|---|---|---|
| unprotected (baseline) | WROTE | WROTE | WROTE |
| seccomp persist gate (watches `openat`) | **WROTE** | **WROTE** | denied |
| Landlock | denied | denied | denied |

The seccomp gate watches `openat` and misses `open` and `creat`; both write the persistence file
unhindered. Landlock governs all three at the single file-open hook.

## What Landlock fixes, and what it does not

It removes all three filesystem weaknesses the paper measures at once: the TOCTOU (no re-read window),
the syscall-alias coverage gap (one hook, not a syscall list), and the `strstr` false-positive/evasion
trade-off (it resolves real paths against an allowlist rather than matching substrings). It is the
correct successor for the *filesystem persistence* policy.

It is not a total replacement. Landlock governs filesystem access and, in recent ABIs, TCP
connect/bind; it does not restrict `execve` (a separate concern, handled by the execution policy) or
arbitrary network egress beyond TCP bind/connect. A complete sandbox pairs a Landlock filesystem
allowlist with a separate execution and network policy. Scope of this benchmark: single x86_64 host,
Landlock ABI v7; the coverage and race results are host-independent properties of the mechanisms, the
seccomp win-rate is scheduler-dependent as in EXP-11.
