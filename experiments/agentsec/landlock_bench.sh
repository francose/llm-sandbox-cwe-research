#!/usr/bin/env bash
# EXP-LL: benchmark the race-free Landlock successor against the seccomp bypass (EXP-11) and the
# syscall-alias coverage gap (EXP-P8). Same attacks, two controls.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
WT_GATE="$HERE/gate_rootful.c"        # persist-capable gate (superset, on this branch)
OUT="$(mktemp -d /tmp/ll_bench.XXXXX)"
RUN="$(mktemp -d /tmp/ll_run.XXXXX)"
ALLOWED="$RUN/allowed"; mkdir -p "$ALLOWED"
BENIGN="$ALLOWED/log.txt"             # inside the Landlock allowlist; no persist token
EVIL="$RUN/authorized_keys"          # outside the allowlist; contains a persist token
N=4000

echo "== build =="
gcc -O2 -pthread "$HERE/toctou_race.c"  -o "$OUT/toctou_race"   && echo "  toctou_race ok"
gcc -O2         "$HERE/open_variants.c" -o "$OUT/open_variants" && echo "  open_variants ok"
gcc -O2         "$HERE/landlock_gate.c" -o "$OUT/landlock_gate" && echo "  landlock_gate ok"
gcc -O1         "$WT_GATE"              -o "$OUT/gate_rootful" -lseccomp && echo "  seccomp gate ok"
LL="$OUT/landlock_gate"; SG="$OUT/gate_rootful"; TR="$OUT/toctou_race"; OV="$OUT/open_variants"

echo; echo "===================================================================="
echo "BENCHMARK 1 -- the EXP-11 TOCTOU race, under each control (N=$N)"
echo "===================================================================="
echo "-- seccomp argument-inspection gate (validates string, kernel re-reads):"
"$SG" --persist "$TR" race "$BENIGN" "$EVIL" $N 2>&1 | grep TOCTOU_RESULT | sed 's/^/   /'
echo "-- Landlock default-deny allowlist (in-kernel, resolved path, no re-read window):"
"$LL" "$ALLOWED" "$TR" race "$BENIGN" "$EVIL" $N 2>&1 | grep TOCTOU_RESULT | sed 's/^/   /'

echo; echo "===================================================================="
echo "BENCHMARK 2 -- syscall-alias coverage: write the persistence path 3 ways"
echo "===================================================================="
echo "-- unprotected (baseline, no gate):"
"$OV" "$EVIL" | sed 's/^/   /'; rm -f "$EVIL"
echo "-- seccomp persist gate (watches openat only):"
"$SG" --persist "$OV" "$EVIL" 2>/dev/null | grep -E 'open=' | sed 's/^/   /'; rm -f "$EVIL"
echo "-- Landlock (governs open/creat/openat at one hook):"
"$LL" "$ALLOWED" "$OV" "$EVIL" 2>/dev/null | grep -E 'open=' | sed 's/^/   /'; rm -f "$EVIL"

rm -rf "$OUT" "$RUN"
