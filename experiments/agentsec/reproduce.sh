#!/usr/bin/env bash
# reproduce.sh -- self-contained rebuild + verification of the exp/01 headline results.
#
# From a fresh checkout of this branch:  bash experiments/agentsec/reproduce.sh
#
# Builds every binary from committed source into a repo-local out/ dir, then runs and PASS/FAILs:
#   EXP-11  TOCTOU defeat of the --persist rootful gate (3 conditions)
#   EXP-12  fp_corpus false-positive / selectivity confusion matrix (TP=7 FP=4 TN=6 FN=0)
#   P12     language-invariance: second execve denied for C / Python / Shell
#   P4      "two forces, one footprint" refuted (footprints non-identical; unlink/rmdir escape)
#
# All scratch state lives in a mktemp run dir + /tmp/fp_run (created by fp_corpus.py); no real
# file outside the workspace is touched. EXP-11's race win-rate is scheduler-dependent (~15-70%);
# its conditions PASS on win>0, not a fixed rate.
#
# Requires: gcc, libseccomp-dev (seccomp.h), python3, unshare (user+net ns), a Linux host.
set -u -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/out"
RUN="$(mktemp -d)"
trap 'rm -rf "$RUN"' EXIT
mkdir -p "$OUT"

PASS=0; FAIL=0
ok()   { printf '  PASS  %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  FAIL  %s\n' "$*"; FAIL=$((FAIL+1)); }
hdr()  { printf '\n=== %s ===\n' "$*"; }

# run the rootful gate inside a rootless user+net namespace when available (matches invariance.py /
# persistence.py); fall back to a direct run if unshare is unavailable.
if unshare -rn true 2>/dev/null; then WRAP=(unshare -rn); else WRAP=(); echo "[i] unshare -rn unavailable; running gate directly"; fi

field() { grep -oE "$1=[0-9-]+" | head -1 | cut -d= -f2; }   # field NAME from a line on stdin

# ---------------------------------------------------------------- build
hdr "BUILD (committed source -> $OUT)"
build() { echo "  cc $1"; if "${@:2}"; then :; else echo "  BUILD FAIL: $1"; exit 2; fi; }
build gate_rootful  gcc -O1 "$HERE/gate_rootful.c"          -o "$OUT/gate_rootful" -lseccomp
build toctou_race   gcc -O2 -pthread "$HERE/toctou_race.c"  -o "$OUT/toctou_race"
build fp_probe      gcc -O2 "$HERE/fp_probe.c"              -o "$OUT/fp_probe"
build spawn_sh_c    gcc -O1 "$HERE/p12_lang/spawn_sh.c"     -o "$OUT/spawn_sh_c"

GATE="$OUT/gate_rootful"; RACE="$OUT/toctou_race"

# ---------------------------------------------------------------- EXP-11
hdr "EXP-11  TOCTOU defeat of the --persist rootful gate"
N=4000
B="$RUN/log.txt"; E="$RUN/authorized_keys"

# A. no gate, race -> the race mechanism itself must win at least once
a=$("$RACE" race "$B" "$E" $N 2>&1 | grep TOCTOU_RESULT); echo "  A $a"
a_win=$(printf '%s' "$a" | field win)
[ "${a_win:-0}" -gt 0 ] && ok "A no-gate race: win=$a_win > 0" || bad "A no-gate race: win=${a_win:-?} (expected >0)"

# B. gate --persist, DIRECT -> the gate must catch every direct attempt (control)
b=$("${WRAP[@]}" "$GATE" --persist "$RACE" direct "$B" "$E" $N 2>&1 | grep TOCTOU_RESULT); echo "  B $b"
b_win=$(printf '%s' "$b" | field win); b_den=$(printf '%s' "$b" | field denied)
{ [ "${b_win:-1}" -eq 0 ] && [ "${b_den:-0}" -eq "$N" ]; } \
  && ok "B gate+direct: denied=$b_den == N=$N and win=$b_win == 0" \
  || bad "B gate+direct: denied=${b_den:-?} win=${b_win:-?} (expected denied=$N, win=0)"

# C. gate --persist, RACE -> TOCTOU bypasses the gate at least once
c=$("${WRAP[@]}" "$GATE" --persist "$RACE" race "$B" "$E" $N 2>&1 | grep TOCTOU_RESULT); echo "  C $c"
c_win=$(printf '%s' "$c" | field win)
[ "${c_win:-0}" -gt 0 ] && ok "C gate+race: win=$c_win > 0 (TOCTOU bypass; rate is scheduler-dependent)" \
                        || bad "C gate+race: win=${c_win:-?} (expected >0)"

# ---------------------------------------------------------------- EXP-12
hdr "EXP-12  fp_corpus selectivity / false-positive confusion matrix"
# fp_corpus.py reads GATE/PROBE from ./out (set in the script); build dir is ready above.
if python3 "$HERE/fp_corpus.py" >"$RUN/fp.out" 2>&1; then
  cm=$(python3 - "$HERE/fp_corpus_results.json" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]))["confusion"]
print(c["TP"],c["FP"],c["TN"],c["FN"])
PY
)
  echo "  confusion TP FP TN FN = $cm"
  [ "$cm" = "7 4 6 0" ] && ok "EXP-12 confusion matrix TP=7 FP=4 TN=6 FN=0" \
                        || bad "EXP-12 confusion matrix = $cm (expected 7 4 6 0)"
else
  echo "  --- fp_corpus.py output ---"; cat "$RUN/fp.out"; bad "EXP-12 fp_corpus.py errored"
fi

# ---------------------------------------------------------------- P12
hdr "P12  language-invariance (second execve denied across C / Python / Shell)"
cp "$HERE/p12_lang/spawn_sh.py" "$RUN/spawn_sh.py"
cp "$HERE/p12_lang/spawn_sh.sh" "$RUN/spawn_sh.sh"
cp "$OUT/spawn_sh_c"            "$RUN/spawn_sh_c"
chmod +x "$RUN/spawn_sh.py" "$RUN/spawn_sh.sh" "$RUN/spawn_sh_c"
for pair in "C:$RUN/spawn_sh_c" "Python:$RUN/spawn_sh.py" "Shell:$RUN/spawn_sh.sh"; do
  lang="${pair%%:*}"; tgt="${pair#*:}"
  line=$("${WRAP[@]}" "$GATE" "$tgt" 2>/dev/null | grep ROOTFUL)
  de=$(printf '%s' "$line" | field denied_execve)
  echo "  $lang: $line"
  [ "${de:-0}" -eq 1 ] && ok "P12 $lang: denied_execve=1" || bad "P12 $lang: denied_execve=${de:-?} (expected 1)"
done

# ---------------------------------------------------------------- P4
hdr "P4  'two forces, one footprint' -- refuted on the real artifacts"
if python3 "$HERE/p4_analysis.py" >"$RUN/p4.out" 2>&1; then
  read -r ident escapes < <(python3 - "$HERE/p4_analysis_results.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
esc=set(d["B_escapes_execve_connect_gate"])
print(str(d["identical"]).lower(), int({"unlink","rmdir"} <= esc))
PY
)
  echo "  footprints identical=$ident ; unlink+rmdir escape execve/connect gate=$escapes"
  { [ "$ident" = "false" ] && [ "$escapes" = "1" ]; } \
    && ok "P4 footprints non-identical AND unlink/rmdir escape the execve/connect gate" \
    || bad "P4 identical=$ident escapes=$escapes (expected identical=false, escapes=1)"
else
  echo "  --- p4_analysis.py output ---"; cat "$RUN/p4.out"; bad "P4 p4_analysis.py errored"
fi

# ---------------------------------------------------------------- summary
hdr "SUMMARY"
printf '  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] && { echo "  ALL CHECKS PASSED"; exit 0; } || { echo "  SOME CHECKS FAILED"; exit 1; }
