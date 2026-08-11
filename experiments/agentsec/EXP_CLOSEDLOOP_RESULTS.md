# EXP-CLOSEDLOOP: detect, deny, terminate, measured as one chain

Everything else in this repo proves the pieces separately: weak controls are bypassable, object-level
controls deny tested effects, a PID namespace or cgroup terminates a contained tree, completed effects
cannot be reversed. What none of it proves is that a *detection can drive the termination*, or what the
residual damage is between the two. That is this experiment.

`closed_loop.c`, unprivileged. The observer lives outside the boundary it watches: the supervisor is the
grandparent process, outside the agent's PID namespace, holding a seccomp notify listener the agent
handed out. The agent is PID 1 of that namespace with 12 workers under it, all inheriting the filter.
Each worker does continuously countable work and periodically retries a forbidden write. Oracles are
ground truth only -- the canary file on disk, a shared work counter read from outside the namespace, and
a survivor count keyed on the namespace inode.

Run: `gcc -O2 closed_loop.c -o out/closed_loop -lseccomp`, then one invocation per arm.

## Result (5 trials per arm, identical in all 5)

| arm | observer | current call | kill | canary written | bytes | detections | survivors |
|---|---|---|---|---|---|---|---|
| baseline | none | allowed | no | **YES** | 420 | 0 | 0 |
| observe | notify | allowed | no | **YES** | 421 | 421 | 0 |
| enforce | notify | **denied** | no | no | 0 | 421 | 0 |
| latekill | notify | allowed | **yes** | **YES** (20/20) | **1** (19/20) | 1 | 0 |
| closed | notify | **denied** | **yes** | no | 0 | 1 | 0 |

## The four comparisons that matter

**baseline vs observe: detection is not prevention.** Same outcome, 420 bytes against 421. The
supervisor saw and correctly identified all 421 forbidden opens and the canary was written anyway,
because the arm answers `CONTINUE`. This is the only arm in which the forbidden action is permitted to
complete *while being watched*, and it is what separates "we saw it" from "we blocked it". In every
other arm the same mechanism does both and the two claims collapse into each other.

**enforce: denial stops the action, not the actor.** Canary clean, and 421 detections in 1.5 seconds --
the agent retried the same forbidden open 421 times and never stopped. Synchronous denial is sound and
it is not terminal. This is the enumeration finding of EXP-ENUM showing up as a retry rate.

**latekill vs closed: a kill switch cannot substitute for enforcement.** `latekill` detects, allows the
current call, then kills the namespace init. The canary still exists. Over 20 trials at the same
configuration it was created **20 out of 20 times**, carrying the one-byte payload on **19** of those and
empty on **1**, where the `O_CREAT` landed and the `write` did not. That split is the useful detail: the
operation that triggered the detection completes -- the file exists every time -- while work that follows
it in the same code path races the signal. Damage falls from 420 bytes to at most 1, but the file is
created regardless, and no amount of kill-switch speed drives that to zero, because the effect completed
before the trigger existed. Only `closed`, which answers `EPERM` before killing, leaves the canary absent.

**enforce vs closed: this is what the kill buys.** Both keep the canary clean. `enforce` absorbs 421
attempts; `closed` absorbs 1. The kill's contribution is not preventing the detected action -- the
synchronous denial did that -- it is preventing the agent from trying the next 420 routes.

So the two mechanisms are not substitutes and the order is not arbitrary. **Deny synchronously, then
terminate.** Denial keeps the current effect from landing; termination keeps the agent from enumerating
past it. A design with only the first survives 421 retries; a design with only the second lets the first
operation through every time.

## Scope, and what these numbers are not

Single x86_64 host, kernel 6.18.33.2 (WSL2), libseccomp 2.5.3, unprivileged user + PID namespaces.

The counts are a property of the fixture, not a damage rate for anything real, and we checked that rather
than asserting it. Sweeping the worker count and run length across four configurations (6/1000,
12/1500, 24/2000, 40/2500) scales the attempt counts with them -- baseline writes 210 bytes at 6 workers
for 1 s and 840 at 24 workers for 2 s. What is structural, and what the fixture was built to expose, is
the *shape*: baseline and observe write the canary, enforce and closed do not, latekill completes exactly
the one operation it detected. The identical numbers within a single configuration come from the fixed
attempt rate and are not evidence of low variance in any general sense -- the one place we looked for
variance, `latekill`'s residual, has some (19/20 versus 1/20).

`latekill`'s residual is at most 1 byte because this fixture writes 1 byte per attempt. The general claim
is "the detected operation completes", measured in operations rather than bytes. For a fixture that wrote
a megabyte or opened a socket and sent a packet, the residual would be a megabyte or a packet.

No latency figures are reported. Detection here is effectively instantaneous because the workers attempt
the forbidden open on their first iteration, so the timing fields measure how soon the agent tried, not
how fast the observer is; and this host's emulated non-`systemd` kernel would not support a credible
latency benchmark anyway (see `EXP_KILLSWITCH_RESULTS.md`).

Filesystem only. There is no network arm -- an egress canary reaching a controlled receiver would need a
separate fixture, and the network invariant is enforced in this repo by an empty namespace rather than by
a notify supervisor, so it is a different chain.

This is also a within-boundary experiment. The observer is outside the agent's PID namespace but on the
same kernel. It says nothing about an escape that compromises the kernel itself, where the observer is
part of what was compromised; that needs a hypervisor-level observer and a disposable VM, which is not
this host.
