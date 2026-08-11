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

It is not a total replacement. Benchmark 3 measures where it stops.

## Benchmark 3 -- where the allowlist stops governing

`landlock_scope.c`, three cases, each in its own child (`landlock_restrict_self` is irreversible per
thread). The oracle is the kernel's errno, never a text scan. Loopback is brought up inside the netns
so UDP and raw datagrams reach the stack; without a route they return `ENETUNREACH`, which is the
network's answer and not Landlock's.

| case | measured | reading |
|---|---|---|
| A `execve` outside an allowlist, `handled_access_fs = EXECUTE` | **denied (EACCES)** | Landlock *can* govern execution; `LANDLOCK_ACCESS_FS_EXECUTE` is bit 0 and has existed since ABI v1 |
| B `write()` through an fd opened *before* `restrict_self` | **WROTE** | a descriptor that predates the ruleset keeps its open-time rights |
| B `open()` of that same path *after* `restrict_self` | denied (EACCES) | the path itself is governed; only the existing descriptor is not |
| C TCP `connect()` under `handled_access_net = CONNECT_TCP` | denied (EACCES) | the network hook works as documented |
| C UDP `sendto()` under the same ruleset | **ALLOWED** | not mediated |
| C raw-socket `sendto()` under the same ruleset | **ALLOWED** | not mediated |

Three corrections to the earlier reading of this experiment:

1. **`execve` was wrong.** This document and the paper both said Landlock "does not restrict
   `execve`." It does. What is true is narrower: `landlock_gate.c` does not *handle*
   `LANDLOCK_ACCESS_FS_EXECUTE` (see the comment at `landlock_gate.c:52` -- reads and exec are left
   ungoverned so the loader works), so execution is unrestricted *in our configuration*. That is an
   implementation choice, not a limit of the mechanism.
2. **Pre-open descriptors are a real gap**, and it is the one that bears on the paper's own
   recommended fix. A supervisor that opens a file and hands the descriptor to the sandboxed target
   (`SECCOMP_IOCTL_NOTIF_ADDFD`) is handing over a descriptor opened outside the domain.
3. **The network ceiling is TCP.** UDP and raw sockets pass a `CONNECT_TCP` ruleset untouched, so an
   egress claim cannot rest on Landlock alone. UDP access rights are attributed to ABI v10, which is
   in no released kernel; this host runs the highest ABI it can and gets v7.

## Benchmark 4 -- the same open, submitted asynchronously through io_uring

| control | direct `openat` | ring `openat` | file created |
|---|---|---|---|
| unprotected baseline | opened | opened | yes |
| seccomp persist gate | denied (EPERM) | **opened** | **yes** |
| Landlock allowlist | denied (EACCES) | denied (EACCES) | no |

The seccomp gate is bypassed outright -- `SCMP_ACT_NOTIFY` sits at syscall entry and the ring never
goes there. Landlock follows the work onto the ring, because it hooks the LSM and `io_uring` runs
submitted work under the submitter's credentials. Full write-up and the list of what this does *not*
cover: `EXP_IOURING_RESULTS.md`.

Scope of this benchmark: single x86_64 host, Landlock ABI v7; the coverage and race outcomes follow from
the documented mechanism semantics and were demonstrated on this one host, the seccomp win-rate is scheduler-dependent as in
EXP-11 (five runs to date, band 18.9%-23.1%).
