#!/usr/bin/env bash
# reproduce_part3.sh -- reproducibility gate for the Part III agent-behaviour tier.
#
# reproduce.sh covers the kernel-mechanism results (TOCTOU, selectivity, io_uring, footprint). It
# deliberately does NOT touch Part III, because agent behaviour needs a live model. This script fills
# that gap for the local-model tier.
#
# What it establishes, precisely: that two runs at the same seed produce a byte-identical escalation
# tree on THIS host and build. That empirical equality is the whole determinism claim. The model's
# file format does not establish it and neither does the digest -- ollama documents a content digest
# and a seed option, but neither guarantees byte-identical behaviour across builds, backends, or
# hardware (llama.cpp seed reproducibility is scoped to a fixed build and float-reduction order).
# See https://github.com/ollama/ollama/blob/main/docs/api.md. On PASS the verdict is written to
# determinism_evidence.json, and model_manifest.py reports it as a measured fact; without a recorded
# run a model reads determinism="unverified" no matter how good its digest is.
#
# Defaults match the published EXP-ENUM experiment: qwen2.5-coder:7b, 11 steps, 2 trials, 4 goals.
# Anything smaller demonstrates a deterministic trajectory but is NOT a reproduction of the paper's
# table, and the script says so rather than letting a fast run be mistaken for the real one.
#
# Note on trials: at a single seed the 2 trials are duplicate trajectories by construction. That is
# a repeatability check. It cannot estimate behavioural variability -- for that you need varied seeds,
# which is a different experiment and not byte-reproducible.
#
# ":cloud"/remote tags are tag-only: the provider can swap the served checkpoint under the same tag,
# so they are dated observations. repro_enum refuses them without --allow-unpinned.
#
# Requires: python3, a reachable local Ollama (127.0.0.1:11434) with the model below pulled.
# Exit codes:  0 = PASS   1 = FAIL (runs diverged)   77 = SKIPPED (no model server; NOT a pass)
set -u -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAPER_MODEL="qwen2.5-coder:7b"       # the model behind the published EXP-ENUM table
PAPER_STEPS=11
PAPER_TRIALS=2
MODEL="${1:-$PAPER_MODEL}"
SEED="${SEED:-42}"
STEPS="${STEPS:-$PAPER_STEPS}"
TRIALS="${TRIALS:-$PAPER_TRIALS}"
R1="$(mktemp)"; R2="$(mktemp)"
trap 'rm -f "$R1" "$R2"' EXIT

hdr() { printf '\n=== %s ===\n' "$*"; }

hdr "OLLAMA REACHABILITY"
if ! curl -fsS -m 5 http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
  echo "  SKIPPED  local Ollama not reachable on 127.0.0.1:11434 -- the Part III tier needs a live model."
  echo "           start it with 'ollama serve &' and pull $PAPER_MODEL, then re-run."
  echo "           exiting 77 (skipped): a reproducibility gate that did not run is not a gate that passed."
  echo "           reproduce.sh kernel results are unaffected and are the model-free tier."
  exit 77
fi
echo "  ok    Ollama reachable"

if ! curl -fsS -m 5 http://127.0.0.1:11434/api/tags 2>/dev/null | grep -q "\"$MODEL\""; then
  echo "  SKIPPED  model $MODEL is not present locally (pull it with: ollama pull $MODEL)"
  echo "           exiting 77 (skipped)."
  exit 77
fi

hdr "SCOPE OF THIS RUN"
if [ "$MODEL" = "$PAPER_MODEL" ] && [ "$STEPS" = "$PAPER_STEPS" ] && [ "$TRIALS" = "$PAPER_TRIALS" ]; then
  echo "  full   matches the published EXP-ENUM configuration ($PAPER_MODEL, $PAPER_STEPS steps, $PAPER_TRIALS trials)"
  SCOPE=full
else
  echo "  REDUCED  running $MODEL, $STEPS steps, $TRIALS trials"
  echo "           published EXP-ENUM is $PAPER_MODEL, $PAPER_STEPS steps, $PAPER_TRIALS trials."
  echo "           a PASS here shows a deterministic trajectory on a smaller configuration; it does"
  echo "           NOT reproduce the paper's table. Run with no arguments for the full experiment."
  SCOPE=reduced
fi

hdr "MODEL PROVENANCE (identity and determinism are separate facts)"
python3 "$HERE/model_manifest.py"

hdr "DETERMINISM GATE  (model=$MODEL seed=$SEED steps=$STEPS trials=$TRIALS)"
echo "  run 1 ..."; python3 "$HERE/repro_enum.py" --models "$MODEL" --seed "$SEED" \
  --steps "$STEPS" --trials "$TRIALS" --served-date reproduce-part3 --out "$R1" | sed 's/^/    /'
echo "  run 2 ..."; python3 "$HERE/repro_enum.py" --models "$MODEL" --seed "$SEED" \
  --steps "$STEPS" --trials "$TRIALS" --served-date reproduce-part3 --out "$R2" | sed 's/^/    /'

hdr "VERDICT"
# --record writes the empirical verdict; only a full-scope run is allowed to stamp the model as
# verified, so a fast reduced run cannot silently upgrade the paper's provenance block.
if [ "$SCOPE" = full ]; then REC=(--record "$MODEL"); else REC=(); fi
if python3 "$HERE/repro_enum.py" --check "$R1" "$R2" "${REC[@]}" | sed 's/^/  /'; then
  if [ "$SCOPE" = full ]; then
    echo "  PASS  EXP-ENUM reproduces byte-identically at seed=$SEED on this host and build"
  else
    echo "  PASS (reduced scope)  a deterministic trajectory at seed=$SEED; not the published table"
  fi
  exit 0
else
  echo "  FAIL  seeded runs diverged -- the determinism claim does NOT hold on this host and build"
  exit 1
fi
