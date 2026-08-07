# EXP-COMPOSED: the assembled sandbox, attacked against five invariants

Part IV assembles the sound successors from Parts I-II into one sandbox and attacks it end-to-end,
binding each invariant to the layer that enforces it rather than defining the invariants as whatever
held. `composed_probe.c` (rootless) covers I1-I3; `killswitch.sh` (privileged) covers I4-I5.
Reproduce the rootless half: `bash landlock_bench.sh` (benchmarks 5 and 6).

| invariant | enforcer | privilege |
|---|---|---|
| I1 filesystem (no write/create/remove outside scratch) | Landlock default-deny allowlist | rootless |
| I2 execution (no execve/execveat) | seccomp SCMP_ACT_ERRNO deny (no CONTINUE to race) | rootless |
| I3 network (no off-host egress) | empty network namespace, no route | rootless |
| I4 process-tree (drive tree to zero live) | cgroup v2 `cgroup.kill` | root (killswitch.sh) |
| I5 resources (pids/memory cap) | cgroup `pids.max` / `memory.max` | root (killswitch.sh) |

## Benchmark 5 -- the composed sandbox under the full matrix (deterministic across 5 runs)

`unshare -rn composed_probe <scratch> <evil> <preopen>` applies Landlock + seccomp-deny to itself,
runs each attack in its own fork child, and reads the oracle from the kernel errno plus ground truth.

| invariant / attack | result | oracle |
|---|---|---|
| I1 `openat` write outside scratch | denied (EACCES) | path absent |
| I1 `open` alias | denied (EACCES) | path absent |
| I1 `creat` alias | denied (EACCES) | path absent |
| I1 `io_uring` `openat` | denied (EACCES) | path absent |
| I1 write inside scratch (control) | SUCCEEDED | file written |
| I1 write through a pre-domain descriptor | **SUCCEEDED** | sentinel leaked |
| I2 `execve` | denied (EPERM) | -- |
| I3 TCP `connect` off host | denied (ENETUNREACH) | no packet |
| I3 UDP `sendto` off host | denied (ENETUNREACH) | no packet |
| I3 raw `sendto` off host | denied (ENETUNREACH) | no packet |

`ORACLE evil_path_exists=no preopen_sentinel_leaked=YES`, identical across 5 runs.

Two readings. The composition is strictly stronger than any single layer: the UDP and raw sockets that
pass a Landlock TCP ruleset untouched (EXP-LANDLOCK benchmark 3) are closed here, because I3 is enforced
by the namespace, not by Landlock. And exactly one attack succeeds -- a write through a descriptor opened
*before* the domain -- which is the pre-open hole of Part II surfacing as a discipline requirement: a
supervisor that hands the target a descriptor opened outside the domain (the ADDFD delegation Part I
recommends) reopens I1 unless that descriptor's rights are constrained. Every attack that acquires its
access *after* the domain is entered is denied.

## Benchmark 6 -- runtime memory mutation from a separate process

`mem_extern.c` reruns the Part I TOCTOU with a different writer: a separate process rewrites the target's
pathname buffer through `process_vm_writev` in the CONTINUE re-read window (the target grants access with
`PR_SET_PTRACER_ANY`). It is one finding shown from a second angle -- the defect is the second read, not
the flip mechanism.

| target | writer | evil opened (win) over N=4000, 5 runs |
|---|---|---|
| seccomp CONTINUE gate | external `process_vm_writev` | 1213 / 1767 / 1141 / 1675 / 1472 -> **28.5%-44.2%** |
| seccomp CONTINUE gate | direct evil open (control) | 0 / 500 -- gate catches every direct attempt |
| Landlock allowlist | external `process_vm_writev` | **0 / 4000** -- immune |

The external writer defeats the gate at least as often as the in-process sibling thread (EXP-11,
18.9%-23.1%). The other named external mechanisms (`/proc/pid/mem`, `ptrace` poke) write the same bytes
to the same address in the same window; not restated as separate findings. `userfaultfd` is the one
variant that would add a property -- pausing the faulting read to make the race deterministic -- and it is
root-gated on this host (`/dev/userfaultfd` is 0600 root, `vm.unprivileged_userfaultfd=0`), so it is left
to the privileged step.

Landlock is immune to the identical flip (win=0/4000): the mutation only changes which *denied* path is
attempted, because the decision is taken at the LSM hook on the resolved object with no user-space check
left to invalidate.

## Scope

Single x86_64 host, Landlock ABI v7, `kernel.io_uring_disabled=0`, Yama `ptrace_scope=1`. I1-I3 and the
memory-mutation coverage are host-independent properties of the mechanisms; the win rates are
scheduler-dependent as in EXP-11. I4-I5 require a delegated cgroup this host does not provide unprivileged
and are measured under root in `killswitch.sh`.
