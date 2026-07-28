# EXP-KILLSWITCH (Part IV, I4/I5): the host-owned cgroup v2 kill switch

The one privileged experiment. I4 (process-tree termination) and I5 (resource bounds) are enforced by a
host-owned cgroup v2, which an unprivileged user is not delegated on this host, so this runs as root:
`sudo bash killswitch.sh`. Reported as a correctness result, not a latency benchmark -- this host is a
non-systemd, emulated (WSL2) kernel whose timing would not support a credible latency figure; a latency
benchmark belongs on a native kernel and is future work.

The agent (`killswitch_agent.c`) is a bounded tree: ~30 persistent workers, each continuously forking
short-lived children, so PIDs churn while the population stays near 90. Each process carries an
`alarm(25-30)` self-terminate so nothing can outlive the experiment even if cleanup fails; every cgroup
also gets `cgroup.kill` + `rmdir` on teardown.

## Result (20 trials each for the two kill methods)

| invariant / mechanism | measurement | result |
|---|---|---|
| I4 PID-enumeration sweep (snapshot `cgroup.procs`, signal each) | survivors over 20 trials | **8/20** -- a child forked after the snapshot is not in the kill list |
| I4 `cgroup.kill` (kernel terminates the subtree) | survivors over 20 trials | **0/20** |
| I4 `cgroup.kill` | work landing after the trigger | 338 counter increments, then `populated 0` |
| I4 `cgroup.freeze` | work advance while frozen (0.7 s) | 0 (98 procs present and inspectable) |
| I5 `pids.max`=20 | peak processes / fork denials | 20 / 2078 |
| I5 `memory.max`=64 MB | a 256 MB allocation | OOM-killed (exit 137), host unaffected |

`KILLSWITCH_RESULT trials=20 enum_left_survivors=8 cgroup_kill_left_survivors=0 kill_post_trigger_writes=338 frozen_advance=0`

## Reading

The 8/20 is a property of the fork rate, not a constant; the asymmetry is not. A tree that does *not* fork
during teardown is cleared by either method -- an earlier, reactive-respawn agent that only re-forked on a
worker's death left 0/20 under *both* methods, because nothing was forking in the enumeration window. The
race needs a concurrently-forking workload to appear at all, which is exactly the workload cgroup.kill was
added to handle. `cgroup.kill` terminates the whole subtree in the kernel, so it is 0/20 regardless of fork
rate; it is not instantaneous (338 increments land between the trigger and quiescence) but it reaches
`populated 0` with no survivors every time.

`cgroup.freeze` quiesces the tree deterministically (work advance 0 over 0.7 s), so a supervisor can
snapshot state without the tree racing it. The resource caps bound the tree: `pids.max` holds the
population at its limit against a tree trying to exceed it, and `memory.max` OOM-kills an over-allocating
process inside the cgroup without touching the host.

I4 and I5 hold: the kill switch drives the whole tree to zero live processes where PID enumeration races,
freezing quiesces it first, and the resource caps bound it.

## Scope

Single host, cgroup v2 unified hierarchy, run as root. The survivor *rates* are workload- and
scheduler-dependent; the qualitative properties -- cgroup.kill is race-free where PID enumeration is not,
freeze quiesces, caps bound -- are host-independent properties of the mechanisms. Latency is not reported
(see above).
