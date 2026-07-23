# Summary — Agent Behavior at the Syscall Boundary

Quick read of where this project landed. Full detail: `HYPOTHESIS_REGISTER.md` (the scoreboard),
`reviews/SYNTHESIS.md` (the critique), `experiments/agentsec/EXP*_RESULTS.md` (one per experiment).

## The question
You cannot trust an LLM agent's intent, output, or reasoning. So test the **deterministic gate at the
syscall boundary**, not the stochastic agent. Locked discipline: nothing is written as a claim unless the
register marks it **SURVIVED** — tested by the mechanical oracle (compile/run/measure), never text-scan.

## Scoreboard

| Hypothesis | Outcome | One line |
|---|---|---|
| P1 observability | SURVIVED | strace oracle works; foundational |
| P9 detection can't certify | SURVIVED | 10/10 detectors incl ASan miss intra-object overflow |
| P2 injection rates | SURVIVED (scoped) | measured; 3 local models, 1 host |
| P3 autonomous destruction | SURVIVED (tiny) | emergent; prompts never instruct it |
| P12 generality (language) | SURVIVED (partial) | interception invariant across C/Python/shell; arch axis open |
| **P11 gate can be defeated** | **SURVIVED** | **TOCTOU bypasses the rootful gate ~20%/attempt, ~100% w/ retry** |
| P5 determinism | TRIVIAL | true but definitional; not soundness |
| P4 two forces one footprint | REFUTED | overlap on execve, but 18% autonomous escapes via unlink/rmdir |
| P6/P7 gate catches it | REFUTED (adversarial) | holds only vs non-adversarial artifacts |
| P8 blocklist complete | REFUTED | io_uring, open/openat2/creat, UDP egress, arch numbering gaps |
| P14c cadence attribution | REFUTED | random-sleep script indistinguishable from live agent |
| P13 CoT divergence | TESTED, forensic/demoted | weak, injection-confined (22%/0%/0%); can't gate |
| P14g gate-reaction | TESTED, forensic/demoted | agent adapts 90%, never stops; spoofable |

## Headline findings

- **The argument-aware gate is bypassable (EXP-11).** It blocks the direct persistence write 4000/4000,
  but a threaded TOCTOU race on the `SECCOMP_USER_NOTIF_FLAG_CONTINUE` allow-path (supervisor validates
  the path, kernel re-reads the pointer) opens the file ~20% per attempt — ~100% with a few retries.
  Existence is host-independent; the exact rate is scheduler-dependent.
- **"Two forces, one footprint" is false (P4).** Injection is 100% `execve`; autonomous is 82% `execve`
  + 18% direct `unlink`/`rmdir` the injection never uses. Footprint is set by *mechanism*, not *force* —
  and that 18% is a blind spot in any execve/connect-only gate.
- **Interception is language-invariant (P12).** C, Python, and shell all get the shell-spawn denied
  identically — the boundary is agnostic to the language that emitted the call.
- **The gate is selective but on a FP/FN Pareto front (EXP-12).** Not deny-all (allows benign), but its
  `strstr` tokens either false-positive on benign lookalikes (un-anchored) or are evadable by path
  normalization (anchored). It can't be both precise and evasion-resistant without real canonicalization.
- **Behavioral attribution doesn't work as a control.** Cadence is spoofable (EXP-14); CoT divergence is
  weak and only a manipulated agent matters, which can fake it (P13); a denied agent *enumerates
  alternatives* rather than stopping (P14g) — 90% adapt, 0% stop. Denial elicits enumeration, not deterrence.

## Two corrections we made to our own reviewers
- The `execve` launch-path TOCTOU the reviewers cited is **not** raceable on this gate (single-threaded,
  pre-target). The exploitable path is the persistence file-op. The bug is real; it was on the wrong syscall.
- "Can't tell the gate from deny-all" holds for the *rootless* gate only; the *rootful* gate is genuinely
  selective (EXP-12).

## Bottom line
This is a **measurement + attack** result, not a "certifiable gate." What survives:
1. Detection can't certify, so observe at the syscall boundary (language-invariant).
2. The boundary gate is **deterministic but not sound** — bypassable (EXP-11), incomplete (P4/P8), and its
   matching trades false positives against evasion (EXP-12).
3. Attacker- and self-driven behavior overlap on `execve` but don't collapse to one footprint, and a
   denied agent enumerates rather than stops. **What protects is coverage, not the control's determinism
   or any behavioral profiling.**

## Reproduce / status
- `bash experiments/agentsec/reproduce.sh` → 8/8 checks (EXP-11, EXP-12, P12, P4), rebuilds from source.
- Everything is on branch `exp/01-invariance`; `main` and `exp/07-persistence` also on origin.
- **Deferred by request:** remediation + suggestions (to the end). Open: P12 architecture axis (needs a
  real second-arch host), goal-matched P4 generation. P13/P14g stay forensic — they cannot gate.
