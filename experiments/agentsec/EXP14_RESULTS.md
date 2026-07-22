# EXP-14 cadence pilot — real data, and it refutes the drawing

One host, `qwen2.5-coder:1.5b`, N=18 actions per actor, decision-layer inter-action intervals.
Raw series + stats in `cadence_pilot_results.json`. Reproduce: `python3 cadence_pilot.py`.
This is a **tiny non-adversarial pilot**, not external-validity evidence. It tests exactly one
row of the P14 matrix (execution/decision cadence) and nothing else.

## Numbers (measured)

| actor | mean ms | median ms | std ms | CV | burstiness B |
|---|---|---|---|---|---|
| script (flat out) | 0.005 | 0.004 | 0.006 | 1.14 | +0.07 |
| live agent | 566.0 | 459.6 | 305.6 | 0.54 | -0.30 |
| script_mimic (random sleeps) | 794.9 | 689.0 | 359.5 | 0.45 | -0.38 |

Agent interval range 244–1448 ms; mimic range 254–1328 ms; **15 of 17 agent intervals fall inside
the mimic's range.** Agent loop was genuinely live (emitted `mkdir -p project_directory`,
`cd project_directory`, then degraded into ```bash fences — a real, if weak, small-model agent).

## What it shows

1. **Script-flat-out vs agent separate only on magnitude** — 5 µs vs 566 ms, five orders of
   magnitude. This is the trivial "an LLM is slower than a for-loop" result and is **useless for
   attribution**: a script closes the entire gap by adding sleeps (that is literally what
   `script_mimic` does).

2. **Raw cadence SHAPE does not separate a live agent from a script imitating one.** Agent vs
   `script_mimic`: CV 0.54 vs 0.45, B -0.30 vs -0.38, and 15/17 intervals overlap. A dumb
   random-sleep loop already lands in the agent's region. At N=18 these are not separable. →
   **Empirical confirmation of the reviewers: timing alone cannot attribute actor class.**

## What it refutes — in our OWN diagram (stack v3)

- The agent glyph was drawn **bursty (B>0)**. Measured **B = -0.30 (anti-bursty / regular)**.
  Decision cadence here is fairly steady round-trips, not bursts. The glyph was not supported.
- The script glyph was drawn **metronomic**. Measured **CV = 1.14** — at microsecond scale the
  kernel scheduler jitter (the very "noise floor" row) dominates the 4 µs mean, so it is NOT a
  clean metronome either.
- Both hand-drawn signatures were wrong in the direction the data could check. The picture was a
  conjecture; the conjecture lost.

## What (if anything) survives

Only the parts this pilot did **not** measure:
- **Gate-reaction signal** (stop / repeat / adapt after a denial) — untested. This is the one
  claim not yet killed, because it keys on the *content and closed-loop shape* of retries, not on
  timing. It may also fail; it has to be run.
- **Timing + argument content jointly** — untested.

Bottom line: P14 as a *cadence* discriminator is not supported by the only data we have. Do not
put the v3 cadence glyphs in any paper as findings. If P14 is pursued, the experiment is the
gate-reaction one (denials on, three drivers, separate on retry behavior + argument content), and
it must be allowed to fail.
