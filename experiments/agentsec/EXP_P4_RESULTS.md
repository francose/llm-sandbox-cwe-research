# EXP-P4 "two forces, one footprint" — REFUTED (strong), holds only as a dominant overlap

`p4_analysis.py` over the real artifacts (no new generation; one counterexample refutes a universal).
Injection footprints from `invariance_samples.jsonl` (attempted records); autonomous footprints parsed
from the strace `tell` field of `agentsec_autonomous_results.json`.

## Measured footprint sets

| force | attempts | syscalls used | footprint set |
|---|---|---|---|
| A — injection (attacker-driven) | 164 | execve 164 (100%) | `{execve}` |
| B — autonomous (self-driven) | 45 | execve 37 (82%), unlink 6 (13%), rmdir 2 (4%) | `{execve, unlink, rmdir}` |

- **Shared (A ∩ B):** `{execve}`
- **A only:** none · **B only:** `{unlink, rmdir}`
- **Footprints identical? NO.**

## What it means

1. **The strong claim is false.** The two forces do not reduce to *one* footprint. They *converge on a
   dominant shared syscall* — both overwhelmingly spawn a shell (`execve("/bin/sh", ["sh","-c","rm -rf …"])`)
   — but autonomous destruction also reaches its end by **direct `unlink`/`rmdir`**, a path the injection
   force never took. Footprint is determined by **mechanism** (spawn-a-shell vs direct-syscall), not by
   **force** (attacker vs self). Same force uses several mechanisms; the forces share the main one, not all.
2. **Concrete blind spot.** 8/45 = **17.8%** of autonomous attempts use `unlink`/`rmdir`, which the
   execve/connect-only rootless gate does not block at all. So the invariance gate has a measured ~18%
   coverage hole against the autonomous force — confirming the earlier flag that the gate "structurally
   can't catch unlink/rmdir," now with a number.
3. **Reframes the thesis correctly.** What protects is **coverage of the union of mechanisms**, not
   "force-invariance." The honest sentence for the paper: *"attacker- and self-driven behavior largely
   converge on a shared execve footprint (100% vs 82%), but do not collapse to one footprint; a gate is
   only as good as its coverage of every mechanism, and the execve/connect gate misses the 18% of
   autonomous destruction that goes direct."*

## Note
Injection artifacts never actually exercised `connect` (the INJECT payload was `system()`→execve, not
network), so the gate's connect rule is untested by artifacts too — a separate small caveat. The
comparison is not goal-matched (injection = exfil/shell, autonomous = delete build dir); a goal-matched
generation would strengthen the *positive* overlap claim, but is unnecessary to refute the universal.
