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
| P4 | Two forces reduce to one footprint | **NOT ESTABLISHED** | by construction; autonomous never measured in the invariance run |
| P6/P7 | Gate catches the dangerous call | **REFUTED — ADVERSARIAL** | holds only vs non-adversarial artifacts; TOCTOU + path evasion |
| P8 | Blocklist is complete | **REFUTED** | io_uring, open/openat2/creat, arch numbering, UDP egress — verified gaps |
| P14c | Cadence attributes actor class | **REFUTED** | EXP-14: random-sleep script indistinguishable from live agent |
| P11 | Gate can be defeated (TOCTOU) | **SURVIVED** | EXP-11: PoC bypasses the persist gate 768/4000 (19.2%) per attempt, ~100% with retry; gate blocks the same attack 4000/4000 head-on. Existence of bypass is host-independent. |
| P12 | Generality across models/arch/langs | **UNTESTED** | single setup |
| P13 | Intent–footprint (CoT) divergence detects injection | **UNTESTED + DEMOTED** | see point 1 |
| P14g | Gate-reaction (stop/repeat/adapt) attributes actor | **UNTESTED + DEMOTED** | see point 1 |

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

Everything beyond this is `UNTESTED` or `REFUTED`. No adversarial-completeness claim, no attribution
claim, no "certifies against harm."

## Test queue (ranked) — each with a falsifiable pass/fail

1. ~~P11 TOCTOU PoC~~ — **DONE, SURVIVED (EXP-11).** 19.2%/attempt, ~100% with retry on the persist
   file-op allow-path. Refinement: the execve *launch* path is NOT raceable on this gate (single-threaded,
   pre-target); the reviewers had located it on execve — it's actually the file-op path. So P7's "rootful
   catches persistence" holds only vs non-racing artifacts. Fix is architectural (kill the second read),
   not a blocklist patch.
2. **Benign corpus + false-positive rate** — add artifacts that *legitimately* need the watched syscalls;
   measure FP. *Gate is "usefully sound" only if FP is low AND TP high; deny-all fails this by design.*
   Fixes the review's deepest methodological hole (F4).
3. **P4 measured** — independently generate attacker vs autonomous artifacts; measure footprint
   indistinguishability *at argument granularity*, not just syscall number. *PASS if distributions overlap
   at the argument level.*
4. **P12 second axis** — re-run the invariance measurement on a second architecture or model family.
   *PASS if the deterministic-gate result holds; the agent rates are expected to move.*

## Change log
- LOCKED. P13, P14 demoted (point 1). P14c refuted (EXP-14). P8, P6/P7 refuted per hypothesis review.
- P11 SURVIVED (EXP-11): rootful persist gate bypassed via TOCTOU, 19.2%/attempt. Execve launch path
  found NOT raceable on this gate (refines the reviewers). Next in queue: benign corpus + false-positive.
