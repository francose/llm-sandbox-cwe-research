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

echo; echo "===================================================================="
echo "BENCHMARK 3 -- where the Landlock allowlist stops governing"
echo "===================================================================="
gcc -O2 "$HERE/landlock_scope.c" -o "$OUT/landlock_scope" && echo "  landlock_scope ok"
DENIED="$RUN/denied"; mkdir -p "$DENIED"
# loopback is brought up inside the netns so UDP and raw datagrams reach the stack; without a
# route they return ENETUNREACH, which is the network's answer and not Landlock's.
unshare -rn sh -c "ip link set lo up; exec '$OUT/landlock_scope' '$ALLOWED' '$DENIED' 127.0.0.1" \
  2>&1 | sed 's/^/   /'

echo; echo "===================================================================="
echo "BENCHMARK 4 -- the same open, submitted asynchronously through io_uring"
echo "===================================================================="
gcc -O2 "$HERE/iouring_probe.c" -o "$OUT/iouring_probe" && echo "  iouring_probe ok"
IOU="$OUT/iouring_probe"
echo "-- unprotected (baseline, no control):"
rm -f "$EVIL"; "$IOU" "$EVIL" | sed 's/^/   /'
echo "-- seccomp persist gate (SCMP_ACT_NOTIFY sits at syscall entry):"
rm -f "$EVIL"; "$SG" --persist "$IOU" "$EVIL" 2>/dev/null | grep '^direct=' | sed 's/^/   /'
echo "-- Landlock allowlist (LSM hook, and io_uring carries the submitter's credentials):"
rm -f "$EVIL"; "$LL" "$ALLOWED" "$IOU" "$EVIL" 2>/dev/null | sed 's/^/   /'
rm -f "$EVIL"

echo; echo "===================================================================="
echo "BENCHMARK 5 -- the composed sandbox (Landlock + seccomp-deny + empty netns), full matrix"
echo "===================================================================="
gcc -O2 "$HERE/composed_probe.c" -o "$OUT/composed_probe" && echo "  composed_probe ok"
CP="$OUT/composed_probe"; PRE="$RUN/preopened_sentinel"
rm -f "$EVIL" "$PRE"
unshare -rn "$CP" "$ALLOWED" "$EVIL" "$PRE" 2>&1 | sed 's/^/   /'

echo; echo "===================================================================="
echo "BENCHMARK 6 -- runtime memory mutation from a separate process (process_vm_writev)"
echo "===================================================================="
gcc -O2 "$HERE/mem_extern.c" -o "$OUT/mem_extern" && echo "  mem_extern ok"
MX="$OUT/mem_extern"
echo "-- external process_vm_writev flip vs the seccomp CONTINUE gate (wins the re-read window):"
rm -f "$EVIL" "$BENIGN"; "$SG" --persist "$MX" "$BENIGN" "$EVIL" "$N" 2>&1 | grep MEMEXTERN | sed 's/^/   /'
echo "-- control: direct evil open, no race (gate must deny every attempt, win=0):"
rm -f "$EVIL"; "$SG" --persist "$MX" "$EVIL" "$EVIL" 500 2>&1 | grep MEMEXTERN | sed 's/^/   /'
echo "-- same external flip vs Landlock (resisted: flip only changes which DENIED path is tried, win=0):"
rm -f "$EVIL" "$BENIGN"; "$LL" "$ALLOWED" "$MX" "$BENIGN" "$EVIL" "$N" 2>&1 | grep MEMEXTERN | sed 's/^/   /'
rm -f "$EVIL" "$BENIGN"

rm -rf "$OUT" "$RUN"
