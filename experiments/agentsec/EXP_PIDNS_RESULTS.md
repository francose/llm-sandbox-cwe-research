# EXP-PIDNS (Part IV, I4): a rootless race-free tree kill

`killswitch.sh` needs a writable cgroup, which an unprivileged user is not delegated on every host --
including this one (`mkdir /sys/fs/cgroup/...` returns EACCES for uid 1000). This is the unprivileged
counterpart to it. Put the agent tree in its own PID namespace and kill that namespace's init: when init
dies the kernel SIGKILLs every remaining process in the namespace (`pid_namespaces(7)`), so there is no
member list to snapshot and therefore no window in which a newly forked process can be missed. That is
the same race-freedom property `cgroup.kill` has, reachable without root.

Run: `bash pidns_kill.sh` (no privilege; needs unprivileged user namespaces). Agent is
`killswitch_agent.c` unchanged -- 30 persistent workers each forking short-lived grandchildren, so PIDs
churn continuously. Survivors are counted by PID-namespace inode (`/proc/<pid>/ns/pid`), not by process
name, so the count is exact.

## Result (20 trials per arm, K=30 workers, peak population 93-98)

| arm | mechanism | trials with survivors | total survivors | post-trigger work | mean trigger to zero |
|---|---|---|---|---|---|
| A | PID-enumeration sweep inside the namespace | 0/20 | 0 | 20,667 | 21 ms |
| B | kill the namespace init (kernel reaps the rest) | 0/20 | 0 | 5,805 | 13 ms |
| C | **control**: same single supervisor kill, no PID namespace | **20/20** | **1,864** | -- | -- |

`PIDNS_RESULT enum residual_survivor_trials=0/20 residual_survivors=0 post_trigger_work=20667 mean_trigger_to_zero_ms=21 | init residual_survivor_trials=0/20 residual_survivors=0 post_trigger_work=5805 mean_trigger_to_zero_ms=13 | control trials_with_survivors=20/20 total_survivors=1864`

## Reading

**Arm C is the finding.** Arms B and C issue the *same* kill -- one SIGKILL to the agent's supervisor
process -- against the *same* tree. Inside a PID namespace that one signal takes ~94 processes to zero in
every one of 20 trials. Outside one it takes down the supervisor and nothing else: the whole tree, ~93
processes per trial, survives in every one of 20 trials. The tree does not die because the supervisor
died; it dies because the kernel reaps a PID namespace whose init has exited. Without the control this
would have been unfalsifiable.

**Arm A did not leave survivors here, and that is worth stating plainly rather than dressing up.** The
enumeration sweep raced -- it let 3.6x more work land after the trigger (1,033 counter increments per
trial against 290) and took 60% longer to reach zero -- but every process it missed was a ~20 ms
grandchild that exited on its own before the survivor check. `killswitch.sh` reports 8/20 survivors for
the cgroup version of this arm; the difference is measurement, not mechanism: that arm counted survivors
at a fixed instant, this one polls to quiescence, and this harness enumerates in a single `ls` exec
rather than one `readlink` fork per PID, which narrows the window it is trying to measure. The
enumeration window exists by construction. Whether it yields a *persistent* survivor on a given run
depends on the fork rate, the enumeration implementation's speed, and whether what gets forked is
long-lived. We did not build a workload to force that outcome.

**The kill is not free of side effects.** 5,805 counter increments landed after the trigger across 20
trials in the best arm -- 290 per trial -- between the signal and quiescence. This matches the
`cgroup.kill` finding (338 post-trigger writes) and carries the same limit: the kill bounds damage after
detection, it does not reverse a write, a packet, or an `io_uring` completion that had already finished.

## Scope

Single x86_64 host, kernel 6.18.33.2 (WSL2), unprivileged user + PID namespaces available. The
race-freedom of init-death follows from documented `pid_namespaces(7)` semantics and is demonstrated
here on one host. The timings (13/21 ms) are from an emulated WSL2 kernel and are reported as a relative
comparison between two arms measured the same way, not as a latency benchmark -- see
`EXP_KILLSWITCH_RESULTS.md` for why a latency figure is not claimed on this host.

One thing this arm does *not* give you that `cgroup.kill` does: a PID namespace bounds the tree, it does
not bound resources. `pids.max` and `memory.max` (I5) still need the cgroup, and still need root here.
