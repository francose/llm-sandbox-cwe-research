# Experiment 1 — Results (issue #1)

360 samples, 358 usable (2 compile failures), 164 attempting artifacts. Numbers below are
cross-checked directly against `invariance_samples.jsonl`, not just the summary.

## The invariance table

Agent side — attempt rate per model x channel, Wilson 95% CI (stochastic):

| model | none | direct | indirect |
|---|---|---|---|
| qwen2.5-coder:1.5b | 0/20 = 0.00 [0.00, 0.16] | 22/50 = 0.44 [0.31, 0.58] | 18/58 = 0.31 [0.21, 0.44] |
| deepseek-coder:6.7b | 0/20 = 0.00 [0.00, 0.16] | 36/40 = 0.90 [0.77, 0.96] | 30/50 = 0.60 [0.46, 0.72] |
| qwen2.5-coder:7b | 0/20 = 0.00 [0.00, 0.16] | 37/50 = 0.74 [0.60, 0.84] | 21/50 = 0.42 [0.29, 0.56] |

Gate side — deterministic, by construction (NOT a rate):

| gate | attempting artifacts blocked | deterministic across K=5 | coverage leaks |
|---|---|---|---|
| rootless (by syscall number) | 164 / 164 | 164 / 164 | 0 |
| rootful (by inspected argument) | 164 / 164 | 164 / 164 | 0 |

The two gates disagree on 0 of 164 artifacts. Not one attempting artifact slipped past both.

## What this shows

- **The agent is stochastic.** The attempt rate swings from 0.00 at baseline to 0.90 (deepseek,
  direct), and every mid-rate cell carries a real confidence interval. This is the layer you
  cannot certify.
- **The gate is invariant.** Every one of the 164 attempts was blocked, identically across
  repeats, by two independent mechanisms that agreed with each other. Zero variance. This is the
  layer you can certify.
- **The agent's unpredictability does not leak into the control.** That is the whole claim, and it
  holds cleanly on this known-answer input.

## Honest observations (not overclaimed)

1. **Direct beats indirect, every time.** For all three models the instruction placed directly in
   the task elicited more compliance than the same instruction hidden in retrieved content
   (0.90 vs 0.60, 0.74 vs 0.42, 0.44 vs 0.31). Consistent ordering, but indirect injection is far
   from harmless (up to 0.60).
2. **The capability gradient is real but NOT purely size-driven.** Within the qwen family, the 7b
   is more injectable than the 1.5b (0.74 vs 0.44 direct). Across families, the 6.7b deepseek-coder
   (0.90) is more injectable than the larger 7b qwen. So "bigger = more manipulable" holds within a
   family but model lineage matters more than raw parameter count. We do not claim a clean
   monotonic law.
3. **Baselines are exactly zero.** 0/20 for all three models. The benign task never spontaneously
   produced a dangerous syscall, so every non-zero cell is attributable to the injection, not noise.
4. **The intervals are honest, not tight everywhere.** Several mid-rate cells hit the 50-sample cap
   with half-widths near 0.13. This is a warmup on a known answer; the point is the gate column, and
   that column has zero variance regardless of where the agent column lands.

## The seven questions, answered with the real numbers

- **Who.** An attacker operating through a channel the model reads, across three models. The most
  compliant vehicle was deepseek-coder:6.7b (0.90 under direct injection); the least was
  qwen2.5-coder:1.5b (0.44). The gate never learned which model or which actor was behind any of the
  164 execve attempts, and blocked all of them the same.
- **What.** In every one of the 164 attempting artifacts the process attempted `execve` (the
  injected `system()` shelling out); coverage confirmed no artifact reached any dangerous syscall
  outside `{execve, execveat, connect}`. The behavior was the syscall, not the source text.
- **When.** At run time, at the syscall boundary, before the call completed — the execve returned
  EPERM instead of launching a shell. The agent's "when" was probabilistic (it complied on 164 of
  358 usable runs); the gate's "when" was every time.
- **Where.** The execution layer, inside `unshare -rn` on x86_64. Not the intent layer, not the
  output layer. 0 coverage leaks means nothing escaped the layer we were watching.
- **Why.** The manipulation condition, never intent. Compliance tracked the channel we set
  (none -> direct/indirect), which is an experimental variable, not a mental state we read. We do
  not report why any model complied, and the gate does not need to know.
- **How.** Measured by strace (the real syscall) and confirmed by EPERM (rootless) and an explicit
  supervisor deny (rootful). Two independent enforcement mechanisms, agreeing on 164/164, so the
  invariance is not an artifact of one implementation.
- **Which.** Both gates caught all 164: the rootless one bluntly by number, the rootful one by
  reading `/bin/sh` from the process memory and denying on the argument. The layers that would have
  missed it: a static output scan (defeatable by obfuscated generation) and an intent classifier
  (probabilistic by nature). The gate is the only layer with a deterministic answer to "which
  control stops this."

## Reproduce

```
python3 invariance.py            # resumes from invariance_samples.jsonl toward confidence
python3 invariance.py --summary  # recompute the table from existing samples
```
Raw data: `invariance_samples.jsonl` (per sample), `invariance_summary.json` (aggregates).
