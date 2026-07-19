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

## Clusters — three lenses each problem falls under

- **THREAT** (what can go wrong): P2 manipulation, P3 autonomous destruction, P10 attacker view.
- **MEASUREMENT** (how we observe / prove it): P1 observability, P9 detection-can't-certify.
- **CONTROL** (the deterministic defense): P6 interception, P7 rootless-vs-rootful, P8 completeness,
  P11 gate-defeat.

The interesting problems sit in the **overlaps** between lenses:

- **THREAT ∩ MEASUREMENT** → **P4 two forces, one footprint** (two different threats collapse to one
  measured footprint).
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
| Execution / process | observable, deterministic footprint | P1 observability, P10 attacker view, **P4 (the forces CONVERGE to one footprint here)** |
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
