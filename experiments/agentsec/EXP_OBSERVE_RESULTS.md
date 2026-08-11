# EXP-OBSERVE: the observation channel the target can detect is the one it can evade

"The agent's behaviour is observable at the syscall level" is worth only as much as the observer's
immunity to being noticed. This separates two channels that both give a syscall-level view and differ on
exactly that point:

- **ptrace / strace** -- an attachment the target reads off its own `/proc/self/status` `TracerPid`
- **seccomp user notification** -- a filter the target installed on itself, with no tracer to detect;
  the kernel parks the syscall until a supervisor holding the listener fd answers

`observe_evade.c`, unprivileged (`NEW_LISTENER` under `no_new_privs`). The target is evasive the way real
malware is: one `TracerPid` read decides whether it does the benign thing or the hostile one. Ground
truth is the filesystem after the run, never the target's own report.

Run: `gcc -O2 observe_evade.c -o out/observe_evade -lseccomp`, then the three arms below.

## Result (deterministic, 5/5 runs each)

| arm | observer | target saw | target chose | evil path exists | what the observer recorded |
|---|---|---|---|---|---|
| 1 | none | `TracerPid=0` | evil | **YES** (5/5) | -- (ground truth: the target is hostile) |
| 2 | `strace -f` | `TracerPid=1370623` | benign | no (5/5) | a clean run: **0/5 traces mention the evil path**, 2 benign opens |
| 3 | seccomp notify | `TracerPid=0` | evil | no (5/5) | `openat("<evil>") -> DENY EPERM`, seen and denied 5/5 |

```
ARM 1  AGENT tracer_pid=0        chose=evil   open=ok                    ORACLE evil_exists=YES
ARM 2  AGENT tracer_pid=1370623  chose=benign open=ok                    ORACLE evil_exists=no
ARM 3  SUPERVISOR saw openat("/tmp/.../EVIL_authorized_keys") -> DENY EPERM
       AGENT tracer_pid=0        chose=evil   open=Operation not permitted
       SUPERVISOR_RESULT notifications=2 evil_seen=1 denied=1            ORACLE evil_exists=no
```

## The finding

Arm 2 is the negative result and it is the useful one. `strace` produced a **faithful trace of a run that
was clean because it was being traced**. An analyst reading that log sees two benign opens and no
indication that anything was withheld. The observation did not fail to record what happened; it changed
what happened, and then recorded that correctly. Arm 1 is the control that proves the artifact was
hostile all along.

Arm 3 is the contrast, and it needs stating carefully, because the naive version of it is false.

**A seccomp filter is not invisible.** The same file the target reads for `TracerPid` also reports the
filter, measured directly:

```
  before  TracerPid: 0   Seccomp: 0   Seccomp_filters: 0
  after   TracerPid: 0   Seccomp: 2   Seccomp_filters: 1
```

So a target that wants to know whether it is filtered can find out with the identical one-line read.
What it does not learn from that field is the policy, or whether a supervisor is attached to the
listener and answering.

The difference between the two channels is not detectability. It is **what detection buys the target,
and what it costs the observer's record.**

- Under ptrace, detection produces a *false negative in the evidence*. The target takes the benign
  branch and the tracer records a clean run of a hostile program. The observer's output is wrong, and
  nothing in it indicates that anything was withheld.
- Under a seccomp notify supervisor **that answers with an errno the kernel applies**, detection buys the
  target only the option of not attacking. It cannot make that call succeed, and cannot produce a clean
  record while escaping through it, because the same process decides the call and writes the record. The
  worst case is an agent that declines to act while watched -- a coverage problem, not a corrupted
  verdict.

That scope condition is not optional. A supervisor that answers `CONTINUE` instead reopens the Part I
race exactly: the call is recorded as the benign path the supervisor read, and executed as the path the
kernel re-read. Under `CONTINUE` a notify supervisor *can* be made to certify a lie, at the measured
18.9-23.1% (EXP11). The property below belongs to the deny path, not to notify in general.

That asymmetry is the defensible claim: both channels are detectable, and on the deny path only one of
them can be made to certify a lie.

One availability property fell out of building the probe and is worth recording. A notify filter whose
listener fd is open but unread parks the filtered syscall indefinitely -- the first version of this test
hung until it was killed. A supervisor that stops answering therefore stalls the target rather than
silently permitting it, which is the correct failure direction, but it does mean supervisor liveness is
part of the availability story.

## Scope, and one thing it does not overturn

Single x86_64 host, kernel 6.18.33.2 (WSL2), libseccomp 2.5.3. The evasion is a property of the ptrace
interface -- `TracerPid` is documented process state -- and is demonstrated here on one host.

The obvious question is whether this invalidates the strace-measured footprints the rest of this repo
rests on. It does not, and that is measured rather than assumed. Zero occurrences of `TracerPid`,
`PTRACE_TRACEME`, `ptrace(`, `IsDebuggerPresent`, or `/proc/self/status` across both the generated code
and the run records the footprint claims are drawn from:

| corpus | what it backs | matches |
|---|---|---|
| `experiments/snippets/` + `snippets_pilot/` (228 C files) | the generated-artifact footprints | 0 |
| `invariance_samples.jsonl` (360) | injection | 0 |
| `persistence_samples.jsonl` (240) | persistence | 0 |
| `agentsec_autonomous_results.json` | autonomous destruction | 0 |
| `agentsec_mvp_results.json` | MVP run | 0 |
| `concealment_results.json` | self-description divergence | 0 |
| `frontier_injection_results.json` | frontier axis | 0 |
| `enum_tree_results.json` | enumeration | 0 |

The models did not write anti-debug code, so the footprints recorded for those artifacts are what those
artifacts do.

What it does establish is a scope condition on the method: strace-based footprinting is sound for a
corpus that does not check for a tracer, and is not a safe default for an adversary that might. A
supervisor design that needs to survive a target actively looking for it should hold a notify listener,
not a ptrace attachment.

The deny path here answers `SCMP_ACT_NOTIFY` with an errno the kernel applies. It does not use
`SECCOMP_USER_NOTIF_FLAG_CONTINUE`, which Part~I shows is raceable; `CONTINUE` appears only on the
benign allow path of this probe, where nothing is being decided about a contested argument.
