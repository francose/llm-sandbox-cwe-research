# Hypothesis review — synthesis of four independent Opus 4.8 reviewers

Four reviewers ran cold (no anchoring on each other or on the controller's earlier critique),
each on a distinct lens: methodology/stats, adversary/red-team, systems/OS-seccomp, novelty/prior-art.
Individual reports: `reviews/hyp-review-{methodology,adversary,systems,novelty}.md`.
Controller verified every load-bearing claim against source before writing this.

Convention: **[CONVERGENT]** = reached independently by 2+ reviewers (strong signal).
**[VERIFIED]** = controller confirmed against code at the cited file:line.
**[BRANCH ARTIFACT]** = a reviewer saw a real fact about the tree it read, not a fabrication.

---

## Two false alarms, corrected first

- **"P7 has no artifact / 106 appears nowhere."** BRANCH ARTIFACT. Methodology + systems read the
  `exp/01-invariance` tree; the P7 evidence (`EXP07_RESULTS.md`, `persistence_samples.jsonl` = 240
  samples, `persistence_summary.json` = `"persistence_attempts": 106`) is real and committed on
  `exp/07-persistence` (commit a2382d9). Not fabricated. The *real* finding underneath is H1 below.
- **"gate_rootful.c has no persistence tokens."** BRANCH ARTIFACT. True of the 176-line main copy;
  the 230-line worktree copy adds openat/rename/renameat/renameat2/link/linkat/symlink/symlinkat
  (gate_rootful.c:118-125, worktree). The persist gate exists — on a side branch.

---

## TIER 1 — Fatal. Reframe or fix before the paper goes anywhere.

**F1. "Certify" conflates determinism with soundness.** [CONVERGENT: methodology, novelty, controller]
The gate is deterministic *by construction* — a lookup on a syscall number/argument, zero variance,
trivially true. Soundness (blocks what's dangerous, allows what isn't) is the entire hard problem and
lives in P8 (completeness) + P11 (defeat), both weak/untested. The headline currently claims the easy
half. "Zero variance" is definitionally trivial (novelty). **Fix:** thesis becomes *"the gate's verdict
is deterministic and auditable; its soundness is bounded by its coverage, which we characterize and do
not claim complete."* This turns P8/P11 from embarrassments into the honest limits section.

**F2. The rootful argument-checking is architecturally defeated by TOCTOU on the CONTINUE path.**
[CONVERGENT: adversary, systems] [VERIFIED: gate_rootful.c:163 main / :217 worktree]
On allow, the supervisor validates the pathname read from `/proc/pid/mem`, then returns
`SECCOMP_USER_NOTIF_FLAG_CONTINUE`. CONTINUE makes the kernel **re-read** the pointer argument, so a
racing thread swaps benign->`/bin/sh` (or ->`authorized_keys`) between validation and kernel re-read.
`seccomp_notify_id_valid` (132/162 main, 158/216 wt) only closes the notification-id-reuse race, not
this one. This is the documented seccomp-notify deep-argument TOCTOU; the kernel manual explicitly warns
against CONTINUE for security-relevant argument inspection. **Consequence:** P7's "rootful catches
106/106" holds only vs non-adversarial artifacts. **Fix:** either re-architect (supervisor performs the
action itself, or copies args into supervisor-owned memory / SECCOMP_IOCTL_NOTIF_ADDFD), or explicitly
scope the whole rootful result to a *cooperative-failure* threat model and say so.

**F3. Landlock subsumes the rootful gate's showcase, without its weaknesses.** [UNIQUE: novelty]
Landlock gives unprivileged, race-free, path-based filesystem rules — exactly the persistence use case
the rootful gate demos, but with no TOCTOU and no `strstr` token matching. If the paper does not confront
Landlock by name in Related Work, a program committee rejects on it. **Fix:** position against Landlock
explicitly; the honest angle is "argument inspection via seccomp-notify is the *general* mechanism
(covers exec, connect, arbitrary args), Landlock is the *specialized* fs-only one" — but you must show
you know it exists and why you'd ever pay the TOCTOU cost.

**F4. No benign corpus -> only one confusion-matrix cell exists.** [CONVERGENT: methodology, adversary, controller]
[VERIFIED: agentsec_mvp.py installs a blanket SCMP_ACT_ERRNO deny of execve/execveat/connect with no arg
comparators.] Every 164/164 and 106/106 is true-positives-only, measured on artifacts pre-filtered to be
"attempting." No true-negatives, no false-positives, no false-negatives. The rootless rig literally cannot
distinguish a correct gate from a deny-everything constant, because no benign artifact in the corpus ever
legitimately needs those syscalls. **Fix:** add a benign workload corpus and report a false-positive rate
per gate. Without it, P6/P7 selectivity is asserted, not shown. (Note: the rootful gate *does* discriminate
by argument, so this bites the rootless invariance experiment specifically.)

---

## TIER 2 — Major coverage / external-validity gaps.

**M1. io_uring silently defeats network AND filesystem coverage at once.** [UNIQUE: systems — flagged as #1 gap]
[VERIFIED: no io_uring_* rule in either gate.] One unblocked `io_uring_setup` lets the agent submit
connect/openat/write/unlink/rename as ring operations that never reach syscall-entry seccomp. Execution
stays covered (io_uring has no exec op). This alone breaks "intercepts the dangerous syscall every time"
for egress + persistence. **Fix:** block/deny io_uring_setup (and io_uring_enter/register) in the filter,
or acknowledge it as an explicit out-of-scope boundary.

**M2. The blocklist is only *relatively* complete (P8).** [CONVERGENT: systems, adversary] [VERIFIED]
Missing from the notify/deny sets: `open`, `openat2`, `creat`, `truncate`/`ftruncate`, `sendto`/`sendmsg`
(UDP egress), and the `openat(O_TRUNC)` payload-drop path. Single-arch: i386 `int 0x80` (execve=11) and
x32 compat entries fall through to the default `SCMP_ACT_ALLOW`. **P8 verdict:** absolute completeness is
unachievable with a blocklist — it requires inverting to a default-deny allowlist. Execution is the one
class you *can* close (a 2-entry set: execve/execveat), which is worth stating as the scope of the
certifiable claim.

**M3. P4 "two forces, one footprint" is by construction, not measured.** [CONVERGENT: methodology, novelty, controller]
In the invariance run the autonomous channel produced 0/164 footprints (all 164 = 95 direct + 69 indirect
injection); the autonomous behavior lives in a separate experiment with a *different* payload (echo vs
rm-rf). "One footprint" holds only at syscall-*number* granularity — which contradicts the rootful gate's
own argument-level pitch. **Fix:** independently generate attacker-driven and self-driven artifacts, then
*measure* whether footprints are indistinguishable at the argument level. This is also where P14 lives as
the counter-tension.

**M4. P13 and P14 restate settled prior art and neither can gate.** [CONVERGENT: novelty, adversary, methodology]
P13 (CoT-vs-footprint divergence): CoT unfaithfulness is settled (Turpin 2023, Lanham 2023); divergence is
neither necessary (a faithful *malicious* CoT gives zero divergence) nor sufficient (benign runtime work
diverges). P14 (cadence attribution): Forrest 1996 syscall-IDS lineage + bot-detection; cadence is
attacker-controlled (inject sleeps) so it attributes only *cooperative* actors, and it's confounded
(compiled-binary cadence is author-independent; the rig captures no timestamps). **Fix:** keep both as
framed *future* axes, not results. They sharpen the story; they are not evidence.

---

## TIER 3 — Integrity / hygiene. Reviewers will catch these.

**H1. P7 evidence + the best gate are stranded on `exp/07-persistence`.** [VERIFIED]
The main line shows the 106/106 prose with no reachable data and a gate missing the persist family.
**Fix:** merge exp/07 (data + 230-line gate) into the main line before external review. Fragmentation is
itself a reproducibility finding.

**H2. P7 is the jewel, mis-filed as an aside.** [CONVERGENT: methodology, novelty]
Rootless 0/106 vs rootful 106/106 on a path-defined threat is the one place the gates *diverge* and the
honest systems result. **Fix:** promote to a headline result — subject to the F2 TOCTOU caveat and the F4
benign-corpus fix.

**H3. Stats hygiene.** [methodology] "Baseline exactly zero" ignores the Wilson upper bound (<=0.16 at
these n); the autonomous `blocked` metric is vacuously true on non-attempting records; coverage-leak=0 is
circular under a fixed payload; model tags unpinned. Detector matrix (P9): keep only the intra-object
result — ASan field-padding for intra-object overflow is known (novelty).

---

## Recommended spine (convergent: methodology + novelty)

This is a **measurement paper, not a systems paper.** The deterministic seccomp gate is prior art
(seccomp-BPF 2012, seccomp-notify 2019, gVisor, and "sandbox the agent" is universal: E2B, Code
Interpreter, Docker). The one defensible novel contribution is **operationalizing attacker-free
autonomous destructive-syscall selection (P3) as a mechanically-measured phenomenon on the same footing
as injection** — verified genuinely emergent (prompts never instruct destruction), so it's *method*
novelty (subjects are 1.5b-7b local models, not frontier agents; tasks are selected to tempt the shortcut).

Proposed arc: **P4 (framing) -> P5/P7 reframed honestly (deterministic verdict + the rootless/rootful
divergence, with the TOCTOU and benign-corpus caveats) -> P3 measurement as the payload**, sold to a
measurement venue. Confront Landlock + io_uring in the threat-model/limits section. Cut P13/P14 to future
work. Drop "certify against harm"; keep "deterministic and auditable, coverage-bounded."

## Action checklist (priority order)
1. Reframe thesis away from "certify" -> "deterministic + auditable, coverage-bounded" (F1).
2. Disclose the CONTINUE TOCTOU and re-scope rootful to cooperative-failure, or re-architect (F2).
3. Add Landlock + io_uring to Related Work / limits (F3, M1).
4. Build a benign corpus; report false-positive rate per gate (F4).
5. Merge exp/07 to the main line; promote P7 to a headline (H1, H2).
6. Turn P4 into a measured indistinguishability test, not by-construction (M3).
7. Move P13/P14 to future work (M4).
