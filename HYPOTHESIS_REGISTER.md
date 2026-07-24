# Hypothesis Register — the gate for what may be written

**Operating rule (locked).** Nothing enters the paper as a *claim* unless its hypothesis is
`SURVIVED` — tested by the mechanical oracle (compile/run/measure, never text-scan) and not refuted.
Framing, diagrams, and notes are allowed as scaffolding, but they carry no conclusion. A hypothesis is
only as strong as the last test it passed, and every test must be allowed to fail.

This file is the source of truth for status. `RESEARCH_PROBLEMS.md` is the map; when they disagree,
this file wins.

## Status

| # | Hypothesis | Status | Evidence / why |
|---|---|---|---|
| P1 | Observability — see syscalls, not text | **SURVIVED** | mechanical strace oracle works; foundational |
| P9 | Detection can't certify (static/ASan miss intra-object) | **SURVIVED** | oobm detector matrix, 10/10 miss incl ASan |
| P2 | Injection yields dangerous syscalls; rates exist | **SURVIVED — SCOPED** | pilot + invariance; 3 local models, 1 host, x86_64 |
| P3 | Autonomous destructive shortcut is emergent | **SURVIVED — TINY** | pilot; small models, prompts never instruct it |
| P5 | Gate verdict is deterministic across repeats | **TRIVIAL** | true but definitional; rig can't tell it from deny-all (no benign corpus) |
| P4 | Two forces reduce to one footprint | **REFUTED (strong); dominant overlap only** | EXP-P4: injection {execve} 100%, autonomous {execve 82%, unlink/rmdir 18%}. Shared execve, but autonomous escapes via unlink/rmdir the injection never uses. Footprint set by mechanism, not force; 18% blind spot in the execve/connect gate. |
| P6/P7 | Gate catches the dangerous call | **REFUTED — ADVERSARIAL** | holds only vs non-adversarial artifacts; TOCTOU + path evasion |
| P8 | Blocklist is complete | **REFUTED** | io_uring, open/openat2/creat, arch numbering, UDP egress — verified gaps |
| P14c | Cadence attributes actor class | **REFUTED** | EXP-14: random-sleep script indistinguishable from live agent |
| P11 | Gate can be defeated (TOCTOU) | **SURVIVED** | EXP-11: PoC bypasses the persist gate 768/4000 (19.2%) per attempt, ~100% with retry; gate blocks the same attack 4000/4000 head-on. Existence of bypass is host-independent. |
| P12 | Generality across models/arch/langs | **SURVIVED (language axis); model axis extended to frontier** | EXP-P12: interception invariant across C/Python/shell. EXP-FRONTIER: injection tested on claude-sonnet-5 + gemini-2.5-pro — 0 refusals, direct compliance at local-model rates (Claude 7/7, Gemini 4/5), indirect vendor-split (Claude 0/8, Gemini 6/6). Arch axis still untested. |
| P13 | Intent–footprint (CoT) divergence detects injection | **TESTED (forensic); DEMOTED** | EXP-P13: divergence weak + injection-confined (22% sensitivity, 0% autonomous). Where present it is mechanism-concealment ("append to file" while doing execve). Non-adversarial models mostly narrate faithfully. Not a detector. |
| P14g | Gate-reaction (stop/repeat/adapt) attributes actor | **TESTED (forensic); DEMOTED** | EXP-P14g: live agent adapts 90% / repeats 10% / stops 0% after denial (method-escalation toward fixed goal). human=stop / script=repeat remain definitional; spoofable → not a control. Nugget: denial elicits enumeration, not deterrence. |

## Point 1 — the manipulated-agent chameleon (demotion of P13, P14)

A manipulated agent (injection or malicious operator) can emit *any* behavior — pace like a human,
retry like nmap, stop after one block. So "LLM agent" is not a behavioral class; it is any distribution
the controller chooses. The actor we most want to catch is definitionally the one that can imitate every
other class. Three independent routes reach the same wall:

1. EXP-14 data — a random-sleep script already passes as the agent.
2. nmap throttling — an adaptive adversary stays under any timing threshold.
3. Chameleon — a manipulated agent's behavior is attacker-chosen, not agent-intrinsic.

**Conclusion (itself a result): behavior-based actor attribution is not a security control.** P13 and
P14 are hereby demoted to **forensic / non-adversarial only** — telemetry on cooperative actors, never a
detector against an adversary. They may not appear in the paper as detection claims. What survives point 1
is the thesis' own spine: the only adversarially-robust facts are *what the actor did at the boundary*
(footprint) and *whether it was authorized* (policy at the gate) — not what it looks like. Certify the
gate; do not profile the actor.

## What the current evidence licenses (the only honest paper today)

> Detection can't certify (P9), so observe at the syscall boundary (P1). The gate's verdict is
> deterministic and auditable (P5, narrow sense), but its soundness is coverage-bounded and currently
> incomplete (P8 refuted). Injection and autonomous malfunction both produce dangerous syscalls in this
> setup (P2/P3, scoped).

Two measured results now sharpen this (both host-independent code properties):
- **The rootful argument-gate is bypassable (EXP-11):** a threaded TOCTOU on the CONTINUE allow-path
  opens a persistence file the gate blocks 4000/4000 head-on; 19.2%/attempt, ~100% with retry.
- **The rootful gate is selective but on a FP/FN Pareto front (EXP-12):** it is not deny-all (allows
  benign), yet its `strstr` tokens trade false positives (un-anchored) against evasion (anchored).

Everything beyond this is `UNTESTED` or `REFUTED`. No adversarial-completeness claim, no attribution
claim, no "certifies against harm."

## Test queue (ranked) — each with a falsifiable pass/fail

1. ~~P11 TOCTOU PoC~~ — **DONE, SURVIVED (EXP-11).** 19.2%/attempt, ~100% with retry on the persist
   file-op allow-path. Refinement: the execve *launch* path is NOT raceable on this gate (single-threaded,
   pre-target); the reviewers had located it on execve — it's actually the file-op path. So P7's "rootful
   catches persistence" holds only vs non-racing artifacts. Fix is architectural (kill the second read),
   not a blocklist patch.
2. ~~Benign corpus + false-positive rate~~ — **DONE (EXP-12).** Rootful persist gate has REAL selectivity
   (TN=6, allows benign; not deny-all — rebuts F4 for the rootful gate). But `strstr` tokens sit on a
   FP/FN Pareto front: un-anchored tokens false-positive on benign lookalikes (4/4), slash-anchored tokens
   avoid FP but are exactly the ones evaded by path normalization (EXP-11). Substring matching cannot be
   both precise and evasion-resistant without real path canonicalization.
3. ~~P4 measured~~ — **DONE, REFUTED strong (EXP-P4).** Footprints overlap on execve but autonomous
   escapes via unlink/rmdir (18%) the injection never uses. Footprint set by mechanism, not force.
4. ~~P12 second axis~~ — **DONE, SURVIVED language axis (EXP-P12).** Interception invariant across
   C/Python/shell. Arch axis remains open (needs a real second-arch host).

5. ~~P13 divergence (forensic)~~ — **DONE (EXP-P13).** Weak, injection-confined (22% / 0% / 0%),
   mechanism-concealment where present. Not a detector.
6. ~~P14g gate-reaction (forensic)~~ — **DONE (EXP-P14g).** Agent adapts 90% / never stops; other classes
   definitional; spoofable. Nugget: denial elicits enumeration, not deterrence.

**QUEUE EMPTY — every hypothesis in the register is now tested or explicitly refuted/demoted.**

## Change log
- LOCKED. P13, P14 demoted (point 1). P14c refuted (EXP-14). P8, P6/P7 refuted per hypothesis review.
- P11 SURVIVED (EXP-11): rootful persist gate bypassed via TOCTOU, 19.2%/attempt. Execve launch path
  found NOT raceable on this gate (refines the reviewers).
- EXP-12 done: gate selectivity is real (not deny-all) but strstr tokens are on a FP/FN Pareto front.
- P4 REFUTED strong (EXP-P4): footprint set by mechanism not force; 18% autonomous escapes via unlink/rmdir.
- P12 SURVIVED language axis (EXP-P12): interception invariant across C/Python/shell; arch axis open.
- P13 forensic (EXP-P13): divergence weak/injection-confined, mechanism-concealment. P14g forensic
  (EXP-P14g): agent adapts 90%, never stops — denial elicits enumeration not deterrence.
- ALL register hypotheses now tested or refuted/demoted. Next step is synthesis + remediation (deferred
  to the end by request), not more tests.
