# Research Problems — Agent Behavior at the Syscall Boundary

A working map of the problems this project investigates, so the experiments and the paper
stay tied to real questions rather than drifting. See `problems_venn.svg` for the visual.

## The one problem underneath all of it

You cannot trust the model, its intent, or its output. How do you make an autonomous agent
safe anyway?

## The problems (with current status)

| # | Problem | The question | Tested by | Status |
|---|---|---|---|---|
| P1 | Observability | Can you see what the agent *does* (syscalls) instead of what it writes/claims? | mechanical strace oracle | foundation, solid |
| P2 | Attacker manipulation | Can injection (direct / indirect) make it emit a dangerous syscall, at what rate across models? | injection experiment | done (pilot + invariance) |
| P3 | Autonomous destruction | With no attacker, will it reach for a destructive shortcut on its own? | autonomous experiment | done (pilot) |
| P4 | Two forces, one footprint | Are attacker-driven and self-driven behavior identical at the syscall layer? | both task families | partial — currently by construction, needs scoping |
| P5 | Certifiability | Can you certify the deterministic gate when you can't certify the stochastic agent? | invariance #1 (rate swings vs gate zero-variance) | done — strongest result |
| P6 | Interception | Does the gate block the dangerous syscall every time, regardless of why? | both gates | done for execve/connect only |
| P7 | Rootless vs rootful | Where does number-blocking suffice vs need argument-awareness? | persistence #7 (rootless 0/106, rootful 106/106) | done, not yet in paper |
| P8 | Completeness | Is a deterministic gate only as safe as its blocklist? | stdin scar, missing truncate/rename, path evasion | shown, paper currently overclaims |
| P9 | Detection can't certify | Do static analysis / sanitizers fail (intra-object overflow), motivating the syscall boundary? | detector matrix (10/10 miss, ASan incl.) | done, holds up |
| P10 | Attacker at the low level | As an attacker, what harm can I do and what are the results? | runs through the whole thing | ongoing lens |
| P11 | Can the gate be defeated? | Can an adversary beat the control itself? | TOCTOU (#6), strstr path evasion (../symlink) | NOT tested |
| P12 | Generality | Does it hold across models, harnesses, architectures, languages? | interop track | NOT tested (3 local models, 1 host) |
| P13 | Intent–footprint divergence | Does the model's stated reasoning (chain of thought) match its actual syscalls, and does the mismatch separate injection / autonomous / benign? | (new) capture CoT + diff against the footprint | candidate — not started |
| P14 | Actor attribution (chronological behavior) | From the *timing / cadence / ordering / reaction-over-time* — not the syscall set — can you tell a human from scripted automation from an autonomous agent? Cross-cutting: every layer emits a signature. | (new) live-actor harness (not the artifact rig) → per-layer temporal + argument features → classify actor class | candidate — cross-cutting measurement axis; needs a live-actor harness |

## Clusters — three lenses each problem falls under

- **THREAT** (what can go wrong): P2 manipulation, P3 autonomous destruction, P10 attacker view.
- **MEASUREMENT** (how we observe / prove it): P1 observability, P9 detection-can't-certify,
  P13 intent–footprint divergence, P14 actor attribution (temporal axis).
- **CONTROL** (the deterministic defense): P6 interception, P7 rootless-vs-rootful, P8 completeness,
  P11 gate-defeat.

The interesting problems sit in the **overlaps** between lenses:

- **THREAT ∩ MEASUREMENT** → **P4 two forces, one footprint** (two different threats collapse to one
  measured footprint). **P14 is P4's counter-tension**: the syscall *set* converges, but the *chronology*
  of that footprint (cadence, inter-call intervals, ordering) may re-separate human / script / agent even
  when the calls are byte-identical. P4 says the footprint is one; P14 asks whether time re-splits it.
- **MEASUREMENT ∩ CONTROL** → **P5 certifiability** (you measure the control's invariance, not the
  agent's rate).
- **THREAT ∩ CONTROL** → **P10 attacker at the low level** (the adversary meeting the boundary).
- **THREAT ∩ MEASUREMENT ∩ CONTROL (the center)** → **the core thesis**: certify the deterministic
  control, at the observed syscall boundary, against both forces at once.
- **Spanning everything (external validity)** → **P12 generality**. Until it's tested across models,
  harnesses, and architectures, every claim above is scoped to this setup.

## The stack view (see `problems_stack.svg`)

The same problems, placed by layer. The key idea: certifiability increases as you go DOWN.
Everyone else defends at the top (probabilistic); we defend at the boundary (deterministic).

| Layer | Property | Problems here |
|---|---|---|
| Intent / reasoning | unknowable, stochastic | P2 injection, P3 autonomous, **P4 (the two forces DIVERGE here)** |
| Output / artifact | inspectable but leaky | P9 detectors miss it (static analysis / ASan fail) |
| Execution / process | observable, deterministic footprint | P1 observability, P10 attacker view, **P4 (the forces CONVERGE to one footprint here)**, P14 actor attribution (the *timing* of this layer) |
| The gate / syscall boundary | the one certifiable control | P5 certifiability, P6 interception, P7 rootless vs rootful, P8 completeness, P11 gate-defeat |
| Kernel / OS | where harm lands if unblocked | — |

P4 is the load-bearing insight: attacker-driven and self-driven behavior look different at the
intent layer but reduce to the same footprint at the execution layer, so one control at the
boundary covers both. P12 generality is the envelope around the whole stack (untested).

## How to read the map against the paper

Every experiment maps to a problem, so the work is not drifting. The gap the review found is that
the paper's *prose* claims P6/P7/P8 more strongly than the experiments that landed prove:
- P6 both-gates is injection-only (invariance #1); the rootful gate was never run on the autonomous
  artifacts.
- P7 (the one experiment where the gates diverge) is not in the paper.
- P8 completeness is undercut by the gate's own incomplete blocklist.

So the near-term work is aligning the narrative to the evidence (P5/P6/P7 as the spine), and, if we
want the harder claims, actually testing P11 (gate-defeat) and P12 (generality).

## Ideation log — interceptability, richer decisions, reading the chain of thought

Captured from the "are the bottom outcomes all binary?" thread. Keep for the paper skeleton.

### 1. Binary is the decision, not the observation
The gate's *decision* is binary (allow / deny) only because you cannot half-run a syscall. The
*observation* is high-dimensional: ordered sequence, arguments (path, address, fd, bytes), timing,
frequency. Our gate collapses all of that to one bit per call. "Binary" is a choice we imposed, not
a property of the layer. Three richer decisions are already latent in what we built:
- **Argument-graded** (rootful already does this): deny `unlink` of *this* path, allow *that*.
- **Sequence-graded** (circuit breaker): decide over a window, N suspicious calls -> escalate.
- **A third state: HOLD.** The rootful supervisor pauses the syscall until it responds — so it can
  escalate to a human / policy engine and *ask*, not just allow/deny. allow / deny / hold-and-ask is
  strictly richer, and the mechanism already exists.

### 2. Interceptability is a gradient, with a floor and a ceiling
- **Floor:** anything happening entirely inside the process address space with no syscall is
  invisible to a syscall gate. The intra-object overflow (P9) is the proof — crosses no kernel
  boundary, so it is un-interceptable at this layer by construction. Interception requires the action
  to cross a boundary you are watching.
- **Ceiling:** intent is never mechanically interceptable. You can intercept the *act*, never the
  *reason*.
- So interceptability = "does the action cross an observable boundary, and does that boundary carry
  enough context to decide." Kernel-mediated discrete acts (execve, connect, unlink) score high;
  in-process memory ops score zero. The gradient itself is a finding worth stating.

### 3. Reading the chain of thought = a SECOND interception point (top of the stack)
CoT / plan / tool-call reasoning gives what the syscall never can: *rich* (semantic) and *early*
(before the act). But it is *stochastic and spoofable* — CoT can be unfaithful to actual behavior,
and an injected agent can have a benign-looking CoT while emitting a malicious syscall (or vice
versa). On its own it fails the certifiability test, so it must NOT be the trust boundary.

### 4. The novel move: score the DIVERGENCE between the two points
- Observe intent at the top (CoT): rich, early, untrusted.
- Enforce at the bottom (syscall): binary, late, certified.
- **Measure the gap.** CoT says "write a log" but the process attempts `execve("/bin/sh")` -> that
  mismatch is the injection/deception signal. Neither layer alone yields it; only the correlation
  does. Stays honest: never trust the CoT, use it as a cross-check against the ground-truth
  footprint; the gate still enforces.
- Reframes the stack: **observe at the top, enforce at the bottom, score the gap** between what it
  said and what it did. Intent-agnostic gate = trust boundary; CoT = telemetry; divergence = detector.

### 5. Spawns P13 (intent–footprint divergence)
Testable with what we have: we already capture the syscall footprint; also capture the model's
reasoning trace and diff them. Question: does divergence separate injection vs autonomous vs benign?
Candidate second axis of the paper (the first axis being the certifiable gate).

### 6. Chronological fingerprinting = a THIRD observation dimension (spawns P14)
Same footprint, different *time signature*. We already record what syscalls happen; if we also record
*when* — per-call timestamps, inter-call intervals, ordering, burstiness — the temporal shape of the
footprint may tell apart three actor classes even when the syscall set is identical:
- **Human:** irregular gaps (seconds–minutes), think-time variance, corrections / backtracking,
  no machine-speed bursts.
- **Scripted automation:** near-constant cadence, no think time, deterministic ordering, fixed bursts.
- **Autonomous agent:** reasoning-paced — tool-call + generation latency, semantically-driven ordering,
  self-correction patterns distinct from both human hesitation and script regularity.

Novelty vs. prior art: behavioral biometrics / bot detection usually work at the UI layer (mouse,
keystroke, HTTP cadence). P14 does it at the **syscall boundary** — the same intent-agnostic ground
truth the gate already sees — so attribution rides on the control's own telemetry, no extra trust surface.

This gives a clean **trio of observation dimensions** on one footprint:
- **P1 — what** (the syscall set / sequence): ground truth of the act.
- **P13 — said vs did** (CoT vs footprint): divergence = injection / deception.
- **P14 — who / cadence** (temporal signature): attribution = human vs automation vs agent.

Direct tension with **P4**: P4's whole point is that intent-difference collapses to one footprint, so one
gate covers both forces. P14 asks the sharper question — does the footprint *stay* collapsed under time,
or does chronology re-separate the actors? Either answer is a result: if time re-separates them, attribution
is possible at the boundary; if it does not, P4's collapse is even stronger than claimed.

### Threads to pull next
- (a) richer decision space: hold / escalate / sequence-scoring instead of binary allow/deny.
- (b) the interceptability gradient stated as a law (floor = no-syscall = invisible; ceiling = intent).
- (c) P13 CoT-vs-footprint divergence as a new experiment and a second axis.
- (d) P14 chronological fingerprint: timestamp the footprint, test whether cadence re-separates
  human / automation / agent (P4's counter-tension, and a third observation dimension).

## Chronological behavior as a cross-cutting axis (elevating P14)

P14 was drawn as a box hanging off the execution layer. That undersells it. **Time is orthogonal to the
stack.** Every layer emits a temporal signature, and the three actor classes — human, scripted automation,
LLM agent — leave *different* signatures at *each* layer. So chronology is not one problem in one band; it
is a vertical axis that crosses all of them, the way P12 generality is the envelope and certifiability is
the left-hand gradient. See `problems_stack_v3.svg`.

### The signature matrix (layer × actor)

| Layer | Human | Scripted automation | LLM agent |
|---|---|---|---|
| Intent / reasoning | slow, variable think-time; goals revised; hesitation | none — no reasoning layer; instant branch on config | generation-paced deliberation; explicit plan, then revision |
| Output / artifact | typed/edited over minutes; incremental saves; backtracking | emitted atomically (template render); no edit sequence | streamed at model speed; whole-function bursts; regenerate-on-error |
| Execution / process | irregular command gaps (s–min); REPL/shell pace | metronomic, tight, deterministic ordering, machine-speed | round-trip cadence: a burst of calls per tool-invocation, then a gap for the next model round-trip |
| The gate / boundary | rare denials; **stops after first block** (learns) | **repeats the blocked call at fixed rate** (no learning) | **retries with variation toward the same goal** (adapts) |
| Kernel / OS | scheduler jitter — the noise floor (also the strace-jitter confound); below the attribution plane | — | — |

### Pilot result (EXP-14) — the cadence claim did NOT survive first contact with data

Ran it instead of asserting it (`experiments/agentsec/cadence_pilot.py`, `EXP14_RESULTS.md`).
One host, qwen2.5-coder:1.5b, N=18, decision-layer inter-action intervals:
- script-flat-out vs live agent separate only on **magnitude** (5 µs vs 566 ms) — useless for
  attribution, since a script closes the gap by adding sleeps.
- A dumb **random-sleep script is not separable from the live agent** on cadence *shape*
  (CV 0.54 vs 0.45; burstiness -0.30 vs -0.38; 15/17 agent intervals overlap the script's range).
  → empirical confirmation of the review: **raw cadence cannot attribute actor class.**
- It refuted our own v3 glyphs: the agent measured **regular (B=-0.30), not bursty**; the script
  measured **noisy (CV=1.14), not metronomic** (µs-scale scheduler jitter dominates).

So the v3 cadence glyphs are conjecture the data killed — do not use them as findings. The only
part still standing is the untested **gate-reaction** row (stop/repeat/adapt + argument content),
which keys on retry *content*, not timing. It must be run and allowed to fail.

### Three things this reframe buys (NOTE: item 1 is now refuted by EXP-14; kept for the record)

1. **The least-spoofable signal lives at the gate, not the clock.** Raw inter-arrival timing (execution
   row) is trivially spoofed — an agent that wants to look human injects sleeps (the reviewers' correct
   objection). But the *reaction to a denial over a window* (gate row) is much harder to fake: stop
   (human) vs blind-repeat (script) vs adapt-toward-goal (agent). Attribution should ride on the
   closed-loop response to enforcement, not on idle cadence.
2. **The argument-aware gate is already the sensor.** The rootful gate (P7) reads syscall arguments to
   decide. The same read gives, for free, the *temporal + argument* sequence of attempts and denials — so
   actor attribution is a byproduct of the control we already built, observed exactly at the trust
   boundary. This is why P14 "overlaps everything": it binds the temporal axis to the CONTROL layer.
3. **Timing alone is weak; timing + content is strong.** A script can add random sleeps and random
   retries. What it cannot easily fake is *semantically coherent* adaptation — retrying a different path
   to the *same* objective after a block. That coherence is visible only in the argument content of the
   retries, not their timing. Chronology must be joined to argument analysis to attribute.

### Honest boundaries (reconciling with the hypothesis review)

- **Measurement, never a control.** Attribution informs triage/forensics and can *feed* the gate's
  hold/escalate decision, but it must never *be* the gate — it degrades to chance against an adversary who
  controls timing and retry-shape. It stays in the MEASUREMENT lens. (This is why the review's "cut P14 to
  future work" stands *for the gate paper*; elevating it here makes it the spine of a second, measurement
  paper, not a control claim in paper #1.)
- **Different measurement plane.** The current rig measures a *compiled artifact's* footprint — and a
  binary runs the same regardless of which model wrote it, so it carries **zero** actor cadence. To measure
  actor chronology you must instrument the **live actor loop** (the agent's tool-call stream, the human's
  shell session, the script's driver) over wall-clock time, with a jitter-clean tap (seccomp-notify or raw
  ptrace, not strace). New harness, not a re-run of the old one.
- **Prior art is real.** Forrest 1996 did single-layer syscall-sequence anomaly detection; bot-detection
  did human-vs-bot cadence. The fresh cut is (a) *multi-layer* signatures and (b) the *human vs automation
  vs LLM-agent* three-class attribution — especially the adapt-to-denial signal at the gate. Position
  against that lineage; do not restate it.
