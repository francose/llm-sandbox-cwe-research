#!/usr/bin/env bash
# Replay every crash artifact and bucket it by root cause, so 800+ crashing inputs
# collapse to the handful of distinct bugs behind them. The one bucket that matters for
# exploitability is "AddressSanitizer" (real memory corruption); everything under
# GGML_ASSERT is a reachable-assertion DoS, not a memory primitive.
#
# Usage: FUZZER=<path> ARTIFACTS=<dir> bash triage.sh
set -u
FUZZER="${FUZZER:?set FUZZER to the gguf_fuzzer binary}"
ARTIFACTS="${ARTIFACTS:?set ARTIFACTS to the crash dir}"
export ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 UBSAN_OPTIONS=halt_on_error=0:print_stacktrace=0
tmp="$(mktemp)"
n=0
for f in "$ARTIFACTS"/crash-*; do
  [ -f "$f" ] || continue
  n=$((n+1))
  out="$(timeout 10 "$FUZZER" "$f" 2>&1)"
  if sig="$(echo "$out" | grep -m1 -oE 'ERROR: AddressSanitizer: [a-z-]+')"; then
    echo "ASAN|$sig" >> "$tmp"
  elif sig="$(echo "$out" | grep -m1 -oE 'GGML_ASSERT\([^)]*\)')"; then
    loc="$(echo "$out" | grep -m1 -oE 'gguf\.cpp:[0-9]+|ggml\.c:[0-9]+')"
    echo "ASSERT|$loc $sig" >> "$tmp"
  elif echo "$out" | grep -q 'out-of-memory'; then
    echo "OOM|allocator refused huge request" >> "$tmp"
  else
    echo "OTHER|$(echo "$out" | grep -m1 -oE 'runtime error: [a-z ]+' || echo unknown)" >> "$tmp"
  fi
done
echo "==== triaged $n crash inputs ===="
echo "distinct root causes (count | class | signature):"
sort "$tmp" | uniq -c | sort -rn
echo
echo "MEMORY-CORRUPTION (ASan) buckets: $(grep -c '^ASAN' "$tmp")"
rm -f "$tmp"
