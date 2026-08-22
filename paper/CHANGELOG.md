# Paper versions

## v2 -- August 2026

Built on v1 after a technical review and a round of self-auditing. Five things are new, two are
corrections to claims v1 made, and one is a language pass.

### New results

**Rootless process-tree termination** (`pidns_kill.sh`, `EXP_PIDNS_RESULTS.md`). v1's kill switch needed
root, because it was a cgroup v2 subtree and this host will not delegate a cgroup to uid 1000. A PID
namespace gives the same invariant unprivileged: kill the namespace init and the kernel reaps every
remaining member. Three arms, 20 trials each. The decisive one is the no-namespace control, which left
survivors in 20 of 20 trials -- without it, both namespace arms reading zero would have been unfalsifiable.

**Observation channels are not interchangeable** (`observe_evade.c`, `EXP_OBSERVE_RESULTS.md`). A target
that reads its own `TracerPid` takes the benign branch under `strace` and the hostile one without it. The
trace is a faithful record of a run that was clean because it was being traced, and nothing in the log says
anything was withheld. Under a notify supervisor answering with an errno, detection buys the target only
the option of not attacking.

**Detect, deny, terminate as one chain** (`closed_loop.c`, `EXP_CLOSEDLOOP_RESULTS.md`). v1 proved the
pieces separately. Five arms, observer outside the agent's PID namespace. The finding that matters:
detection followed by a kill is not a substitute for synchronous denial. The `latekill` arm created the
canary file in 20 of 20 trials, carrying its payload in 19. Deny first, then terminate.

**Egress with an arrival oracle** (`egress_oracle.sh`, `EXP_EGRESS_RESULTS.md`). v1's egress evidence was
that `sendto` returned a positive number, which says the sending kernel accepted a buffer and nothing
about where it went. v2 puts a receiver in a network namespace the agent does not own, one veth hop away,
plus an `AF_PACKET` tap as a second witness. Five routes, four arms, 20 trials each. Neither a `connect`
syscall filter nor a Landlock `CONNECT_TCP` ruleset is scoped to object lifetime -- a socket connected
before the policy delivers 20/20 under both.

**Model provenance split into two axes** (`model_manifest.py`, `determinism_evidence.json`).
Content-addressed identity (which weights ran) and empirically verified determinism (does the same seed
reproduce on this build) were being reported as one fact. They are not the same fact, and a digest does
not imply the second.

### Corrections to v1

**A seccomp filter is visible to the target.** v1 said a notify listener leaves nothing in the target's own
state to read. It does: `/proc/self/status` reports `Seccomp: 2` and `Seccomp_filters: 1`, measured
directly. The defensible claim is the asymmetry in what detection buys, not invisibility.

**Landlock can govern execute.** `LANDLOCK_ACCESS_FS_EXECUTE` is bit 0 and has existed since ABI v1. The
narrower true statement is that our gate does not handle it.

### Language pass

`host-independent`, `immune`, `provably cannot stop`, and `certify` were all scoped to what was measured on
one host. The method section now states plainly that every bypass in the ledger was written by us and that
no agent found any of them. The escape ledger was renamed to a control-bypass, containment, and termination
ledger for the same reason.

### Cost

18 pages to 23. Sections 14 (egress) and 17 (closed loop) are new, and section 13 grew.

## v1 -- July 2026

Parts I through IV: the argument-inspection gate is bypassable, coverage is incomplete before any race, the
Landlock fix, the denied agent enumerates, the composed sandbox, and a rootful cgroup v2 kill switch.
Condensed from 19 pages to 18 before submission.
