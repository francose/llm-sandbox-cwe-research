# PC Review — Novelty, Framing, and Prior-Art Positioning

**Artifact under review:** `RESEARCH_PROBLEMS.md` (the P1–P14 problem map), read against
`EXP01_RESULTS.md` (invariance), `EXP07_RESULTS.md` (persistence, rootless vs rootful),
`DETECTOR_GAP_RESULTS.md`, `RESULTS.md`, `WORKLOAD_FRAMING.md`, `agentsec_autonomous.py`,
and the current `paper/main.tex` abstract/intro.

**Bottom line up front.** The mechanism at the center of this program — a deterministic
seccomp syscall gate for untrusted code, in an unprivileged (seccomp-BPF) and a privileged
(seccomp user-notification) form, inside a rootless namespace — is not new; it is 2012–2019
Linux plumbing that is standard practice for sandboxing agents today. The defensible
contribution is *not* the gate and *not* the slogan "you can only certify the mechanical
layer." It is a **measurement contribution about agent behavior at the syscall boundary**,
with one genuinely fresh empirical object (attacker-free *autonomous* destructive-syscall
selection, measured on the same mechanical footing as injection) and one honest systems
result the paper currently under-sells (number-blind vs argument-aware enforcement diverging
on a path-defined threat, EXP07). Framed as a systems paper, this reads as "re-skinned
seccomp" and gets rejected. Framed as a measurement study, it has a defensible core. P13 and
P14 are not contributions; they restate two well-established literatures and belong in future
work.

Citations I am confident of are stated plainly; ones a co-author should verify before the
paper cites them are flagged **[verify]**.

---

## (A) The defensible novel contribution(s)

**A1 — Autonomous destructive-syscall selection, operationalized and measured at the
execution boundary (P3, feeding P4/P5). This is the single freshest thing here.**
The injection half of the paper (P2) sits squarely in an existing lineage (Greshake et al.
indirect injection; the agent-harm/agent-injection benchmark wave — see B). The *attacker-free*
half is where I cannot point to a direct prior. Prior agent-safety measurement
(toolemu / Ruan et al., ICLR 2024; AgentDojo, Debenedetti et al., NeurIPS D&B 2024;
AgentHarm, Andriushchenko et al. 2024 **[verify exact venue/year]**) measures agent harm at
the *tool-call / textual* layer, judged by an LLM or a scripted emulator. This program
measures it at the *mechanical syscall* layer — "did the compiled process actually attempt
`execve("/bin/sh", rm -rf …)` or a direct `unlink`" — with the oracle being strace, not a
judge model. Measuring self-selected destruction as a syscall event, on the same footing as
injection, is the novel empirical move.

**Important caveat that bounds the claim (I checked the task design).** `agentsec_autonomous.py`
uses three dual-path tasks (`reset_build`, `reset_test_db`, `free_disk`) whose prompts never
instruct destruction — the `rm -rf` / `dropdb` is the model's own choice, so the behavior is
genuinely *emergent*, not scripted-to-succeed (good, and better than P4, which
`RESEARCH_PROBLEMS.md` itself admits is "by construction"). **But** the tasks are visibly
*selected* so the tempting shortcut is destructive (the verbs "reset the build directory,"
"free up disk space" are close to eliciting the shortcut), and the subjects are 1.5b–7b local
code models, while the motivating incidents ("the agent deleted the production database") are
frontier agents in production harnesses. So the honest, defensible claim is **method
novelty** — "we operationalize autonomous destruction as a measurable syscall-level
phenomenon on dual-path tasks" — not **finding novelty** ("agents self-destruct at rate X").
State the small-model → frontier-incident gap as an explicit validity limit; a PC will raise
it, so owning it is strictly better. (Minor construct-validity note: the code scores
`attempted = destructive_tell OR any exec/connect`, so the broad "attempted" number conflates
"reached for a destructive command" with "called any exec/connect"; the destructive-specific
count is the one to headline.)

**A2 — The stochastic-agent / deterministic-gate *decoupling*, but only if reframed away from
"zero variance" (P5, P7).** "A deterministic filter has zero variance across repeats" is
definitionally true and needs no experiment; do not sell that. The non-trivial question is
**whether the agent's output variance ever routes *around* the gate**, and EXP01+EXP07
together answer it empirically: for a number-expressible threat (`execve`/`connect`) the gate
catches 164/164 regardless of an agent rate that swings 0.44–0.90; for a *path-defined* threat
(write to `~/.ssh/authorized_keys`) the number-blind rootless gate catches **0/106** — agent
output defeats it by default because the malicious `openat` is byte-identical to a benign
`openat` — while the argument-aware rootful gate catches **106/106** and breaks 0 benign I/O.
That contrast is the real result: stochastic output sometimes produces gate-evading footprints
and sometimes cannot, *determined by whether the threat is expressible in the gate's decision
vocabulary*. That is a genuine, if modest, systems finding, and it is currently mis-filed as a
teaching aside (P7 is "done, not yet in paper"). Promote it.

**A3 (thin, keep as a paragraph, not a pillar) — H3: real local models generate the surviving
memory-corruption class, and the shipped static stack catches 0/11.** This is the "open wedge"
`WORKLOAD_FRAMING.md` itself names. Generating C from three models, measuring an ASan-confirmed
spatial-overflow rate (5.2%, 95% CI 3–9%; 14.3% on the 1.5b model, 0% on the 7b), and showing
the commodity static stack diagnosed the overflow in 0/11 confirmed cases, is a small genuine
measurement. Keep it. (See C for what to cut around it.)

---

## (B) Claims that restate prior art — with lineage

**B1 — "A deterministic syscall gate for untrusted code" (P1, P5, P6, and the whole
enforcement half). Prior art; the only new thing is the LLM-agent framing.**
- seccomp-BPF (Linux 3.5, 2012) is exactly the rootless number-matching gate; it is the
  default sandboxing primitive in Chrome, Docker/containerd, systemd, OpenSSH, Firefox.
- seccomp **user-notification** (`SECCOMP_USER_NOTIF`, Linux 5.0, 2019) is *exactly* the
  "rootful" gate: a privileged supervisor pauses a flagged syscall, reads the pointer argument
  from the child's memory, and decides allow/deny live. The paper's rootful gate is a textbook
  instance, TOCTOU race and all — that race is documented prior art, not a new discovery, and
  `WORKLOAD_FRAMING.md` already concedes it.
- gVisor (Google, 2018), nsjail, bubblewrap, minijail, firejail all package
  namespaces+seccomp for untrusted code.
- **Landlock (Linux 5.13, 2021, Mickaël Salaün)** is the sharpest hit — see (D).
None of P1/P5/P6 as *mechanisms* are novel. The intellectual content that survives is the
*measurement* (A1/A2), not the gate.

**B2 — "Sandbox the agent's syscalls" is standard practice, not a proposal.** OpenAI's Code
Interpreter/ChatGPT sandbox (gVisor-class), E2B (Firecracker microVMs marketed explicitly for
AI code execution) **[verify current isolation tech]**, Modal, Daytona, Cloudflare/Fly agent
sandboxes, and Docker's default seccomp profile already do this. The paper must not imply
"agents should be sandboxed at the syscall layer" is a finding; it is the status quo. The
contribution has to be measurement *about* that boundary, not advocacy *for* it.

**B3 — P14 (chronological/cadence actor-attribution at the syscall boundary) restates two
mature literatures.**
- Host IDS by syscall trace: **Forrest, Hofmeyr, Somayaji, Longstaff, "A Sense of Self for
  Unix Processes," IEEE S&P 1996**, and its lineage — Warrender/Forrest/Pearlmutter 1999
  (STIDE/t-STIDE/HMM), Wagner & Dean 2001 (static-model), Sekar FSA, Feng et al. VtPath 2003,
  **Mutz et al., "Anomalous System Call Detection," ACM TISSEC 2006** (anomaly detection on
  syscall *arguments* — directly adjacent to the rootful gate's path inspection), and the
  ADFA-LD benchmark (Creech & Hu, 2013). Profiling a process from its syscall trace to classify
  it *is* this field. Classic work keys on the syscall *sequence/set*; P14's *timing/cadence*
  axis is a different feature family, but "cadence separates automation from human" is itself
  old (below), so P14 lands as supervised classification on syscall traces — anomaly/attribution
  detection with a relabeled target set. As a *novel detector*, high rejection risk.
- Behavioral biometrics / bot detection: keystroke dynamics (Monrose & Rubin), mouse dynamics
  (Ahmed & Traore 2007), reCAPTCHA-style cadence bot detection. "Machine cadence is regular,
  human cadence has think-time variance" is the founding intuition of that field. P14's only
  twist is the layer (syscall vs UI/HTTP) and adding "autonomous agent" as a third class. That
  is at best an incremental relocation of a known idea; `RESEARCH_PROBLEMS.md` already frames it
  correctly as "same idea, different layer," which is exactly why it is not a paper-carrying
  contribution.

**B4 — P13 (CoT-vs-footprint divergence). "CoT can lie" is established; the divergence-scoring
move is fresher but unrun.**
- CoT unfaithfulness is settled: **Turpin et al., "Language Models Don't Always Say What They
  Think," NeurIPS 2023**; **Lanham et al., "Measuring Faithfulness in Chain-of-Thought
  Reasoning," 2023 (Anthropic)**; the reasoning-model follow-ups (Chua/Anthropic 2025
  **[verify]**) and encoded-reasoning/steganography work (Roger & Greenblatt 2023). So P13's
  *premise* is not a claim, it is a citation.
- The *operational* move — treat CoT as untrusted telemetry, the syscall footprint as a
  trusted mechanical oracle, and score the **gap** as an injection/deception signal — is
  closer to novel, but it sits inside the AI-control / monitoring paradigm: **Greenblatt et
  al., "AI Control," 2023/24** (untrusted model + trusted checker), and CoT-misbehavior
  monitoring (OpenAI, Baker et al., 2025 **[verify]**, incl. the "optimize against the monitor
  → it obfuscates" result, which directly threatens P13's spoofability). What would be genuinely
  new is grounding the CoT monitor against an *independent mechanical execution-boundary oracle*
  rather than another LLM judge. That is a real idea — but it is "candidate — not started," so it
  cannot be claimed in this paper. Future work.

**B5 — The detector-coverage matrix (P9 / Finding 1 / DETECTOR_GAP). Largely known.** "Shipped
`-O2 -D_FORTIFY_SOURCE=2` misses most memory-corruption classes" and "intra-object overflow is
invisible to boundary-based tools including ASan" are understood in the sanitizer community;
ASan's own field-padding extension (`-fsanitize-address-field-padding`) exists *specifically*
for the intra-object case, and the paper already cites it (`asanintra`). The report is careful
and honest (it even refutes its own naive version), but as novelty it is a known-result
confirmation. Its *job* in the paper is one motivating paragraph — "output inspection can't
certify low-level harm either" — not a co-headline. (H3, A3, is the part worth keeping.)

**B6 — P4 "two forces, one footprint" is a good framing but near-tautological at the
mechanism level.** No syscall filter has *ever* consulted intent — intent-agnosticism is how
seccomp has always worked, not a discovered property. The genuinely empirical half of P4
(that injection and autonomous selection reach the *same* syscalls in practice) is exactly the
half `RESEARCH_PROBLEMS.md` marks "currently by construction." So P4 as stated is ~80% obvious;
its value is the *framing* (naming autonomous malfunction a co-equal threat), not a result.

---

## (C) Recommended paper spine + what to cut

**Spine (one paper): P4 → P5/P7 → P3, sold as a measurement study.**
1. **Frame (P4):** attacker-driven and self-driven dangerous actions are indistinguishable at
   the syscall boundary, so an intent-agnostic control addresses both. State it as a *design
   framing*, not a finding, and drop any "discovery" language.
2. **Method + headline measurement (P2 + P3 on one footing):** the mechanical strace oracle
   (P1) as method; injection *and* autonomous self-selection measured as syscall attempts.
   Headline the **autonomous** number as method-novel (A1), with the small-model→frontier
   validity limit stated up front.
3. **The enforcement result that actually has content (P5 reframed + P7):** not "the gate has
   zero variance" but "does stochastic agent output route around the gate?" — 164/164 on
   number-expressible threats vs the **0/106 rootless / 106/106 rootful** divergence on a
   path-defined threat. This is the systems payload; promote EXP07 out of the appendix.
4. **One motivating paragraph (P9):** output inspection can't certify low-level harm either —
   cite the intra-object gap and H3's 0/11, then stop.

**Cut to future work (explicitly):**
- **P13 and P14 entirely.** Both restate established literatures (B3, B4) and are unrun. A
  reviewer who sees "candidate — not started" axes pitched as contributions will discount the
  whole submission. One sentence each in Future Work, positioned honestly against Forrest '96
  and Turpin '23.
- **The detector-coverage matrix (P9 Finding 1) as a pillar.** Demote to the single paragraph
  above; keep H3. It is a separate, already-trodden topic (sanitizer coverage of memory bugs).
- **GGUF fuzzing (Finding 6).** A bounded negative result (2 DoS asserts, 0 corruption) on a
  target already under OSS-Fuzz. It is honest but orthogonal to the syscall-boundary thesis;
  it dilutes the spine. Cut or footnote.
- **P8 completeness as a positive claim.** `RESEARCH_PROBLEMS.md` concedes the paper
  "overclaims" here (missing truncate/rename, stdin scar, path evasion). Reframe P8 as a stated
  *limitation* ("a deterministic gate is only as complete as its blocklist / decision
  vocabulary"), which is honest and actually strengthens A2.
- **P11 (gate-defeat) and P12 (generality):** untested; Future Work, named as such.

---

## (D) The biggest positioning risk — what a reviewer rejects over

**The knockout: "This is 15-year-old seccomp plus a namespace, and 'sandbox the agent' is
universal practice. Landlock already gives unprivileged, race-free, path-based file rules that
subsume your one interesting enforcement case. What is the contribution beyond re-skinning
known sandboxing as 'LLM agent security'?"**

- **Landlock is the specific prior art that guts P7 if unaddressed.** The rootful gate's
  showcase win (EXP07: deny the write to `~/.ssh/authorized_keys`, allow the log write, same
  program) is *exactly* what Landlock does — path-scoped filesystem access control, **unprivileged
  and without the TOCTOU race** that the paper's `strstr`-on-live-memory approach carries (and
  which EXP07 concedes is symlink/`..`-evadable). A reviewer will ask why the contribution is a
  privileged, racy re-derivation of Landlock (or an AppArmor/SELinux path rule). The paper must
  confront Landlock *by name* in Related Work and explain the delta — e.g., "we study the
  seccomp-notify point in the design space and its failure mode; a production control should
  likely use Landlock/LSM for the path-defined class," which is honest and defensible. Silence
  here is fatal.
- **"Certify" is doing too much work.** As implemented, "certified" means "deterministic given
  a cooperative, non-adversarial-in-memory child" (WORKLOAD_FRAMING says so), and the rootful
  path check is defeated by a symlink (P11 untested). So the paper cannot claim it *certifies*
  against an adversary. Scope the word to "deterministic under a stated threat model," or a
  reviewer breaks the headline with one `ln -s`.
- **Second-order risk — venue mismatch.** Pitched to a systems-security track (S&P/CCS/USENIX)
  as a *mechanism*, "it's just seccomp" wins. The genuinely new content is a *measurement* of
  agent behavior at the boundary. Choose the measurement framing (and a measurement-friendly
  venue/track); it dodges the mechanism critique instead of walking into it.
- **Third-order — related-work gap.** The paper currently cites essentially Greshake + Pearce
  (Copilot) + seccomp/ASan tooling. It omits the entire agent-safety measurement wave (toolemu,
  AgentDojo, AgentHarm) it is closest to, and the syscall-IDS lineage (Forrest et al.) that P14
  sits inside. A PC reviewer in this area will notice the omissions immediately and read them as
  the authors not knowing their own neighborhood.

---

## (E) Prioritized suggestions to sharpen novelty

1. **Make the autonomous measurement the paper's spine, and make P4's collapse an actual
   measurement, not a construction (highest leverage).** Add task variants where injection and
   autonomous selection are *not* engineered onto the same syscall, and report whether they
   still converge. If they do, P4 becomes empirical instead of tautological; if they diverge,
   that is a *more* interesting result (the gate's coverage must widen). Either outcome beats
   "by construction."
2. **Promote EXP07 to a headline and reframe P5 as "does agent variance route around the
   gate."** The 0/106 vs 106/106 divergence is the strongest honest systems result you have;
   it currently isn't in the paper.
3. **Confront Landlock, AppArmor/SELinux, and the seccomp-notify TOCTOU race head-on in Related
   Work**, and reposition the rootful gate as *studying a point in the design space and its
   failure mode*, not proposing a new mechanism. Add the agent-safety benchmarks (toolemu,
   AgentDojo, AgentHarm) and the Forrest syscall-IDS lineage.
4. **Scope "certify" precisely** to a stated threat model (cooperative, non-adversarial-in-memory
   child; number/path-expressible threats). This turns the biggest overclaim into a strength.
5. **Move P13 and P14 to a clearly-labeled Future Work**, each positioned against its prior art
   (P13 vs Turpin/Lanham + AI-control monitoring; P14 vs Forrest '96 + behavioral biometrics).
   If you ever run P13, its *only* novel hook is CoT scored against a *mechanical* oracle rather
   than an LLM judge — say exactly that and nothing broader.
6. **State the small-model → frontier-agent external-validity gap explicitly** for every
   agent-behavior number. It is the first thing a reviewer challenges; pre-empting it converts a
   weakness into credibility. (P12 generality is currently "3 local models, one host" — say so.)

---

### Citation-confidence ledger
- **Confident:** Forrest et al. IEEE S&P 1996; Warrender/Forrest/Pearlmutter 1999; Wagner &
  Dean 2001; Mutz et al. TISSEC 2006; ADFA-LD (Creech & Hu 2013); seccomp-BPF (3.5, 2012);
  seccomp-notify (5.0, 2019); gVisor (2018); Landlock (5.13, 2021); Turpin et al. NeurIPS 2023;
  Lanham et al. 2023; Greenblatt et al. AI Control 2023/24; AgentDojo (Debenedetti et al. 2024);
  toolemu/Ruan et al. (ICLR 2024); ASan field-padding extension for intra-object.
- **[verify] before citing:** AgentHarm exact venue/year; the 2025 reasoning-model CoT-
  faithfulness paper (Chua/Anthropic); OpenAI CoT-misbehavior-monitoring (Baker et al. 2025);
  E2B's current isolation technology (Firecracker vs gVisor); Monrose & Rubin / Ahmed & Traore
  exact years if used.
