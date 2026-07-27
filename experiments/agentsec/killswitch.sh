#!/usr/bin/env bash
# EXP-KILLSWITCH (Part IV, I4/I5): the host-owned cgroup v2 kill switch, as a CORRECTNESS result.
#
# This is the one privileged step of the artifact: it needs a writable cgroup, which an
# unprivileged user is not delegated on every host. Run it as root:  sudo bash killswitch.sh
#
# It does NOT report a latency benchmark -- this host may be a non-systemd / emulated kernel where a
# latency figure would not be credible (see the paper, Section on the kill switch). It reports the
# host-independent correctness properties:
#   A. concurrent-fork termination: cgroup.kill drives the tree to zero where a PID-enumeration
#      sweep leaves survivors, and the work that lands AFTER each trigger.
#   B. freeze-then-inspect: cgroup.freeze quiesces the tree (no work advances while frozen).
#   C. resource bounds: pids.max caps the process count; memory.max OOM-kills inside the cgroup
#      without touching the host.
#
# The agent tree is bounded (~30 self-respawning workers) -- safe on a workstation, never a fork bomb.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
CGROOT=/sys/fs/cgroup
BASE="$CGROOT/te_killswitch"
WORK="$(mktemp -d /tmp/killswitch.XXXXX)"
AGENT="$WORK/agent"; HOG="$WORK/hog"
K=30

log(){ echo "$@"; }
die(){ echo "KILLSWITCH_ABORT: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "must run as root (sudo bash killswitch.sh)"
[ "$(stat -fc %T "$CGROOT" 2>/dev/null)" = cgroup2fs ] || die "no cgroup v2 at $CGROOT"

cleanup(){
  for cg in "$BASE"/*/ "$BASE"; do
    [ -d "$cg" ] || continue
    [ -e "$cg/cgroup.kill" ] && echo 1 > "$cg/cgroup.kill" 2>/dev/null
    sleep 0.1; rmdir "$cg" 2>/dev/null
  done
  rm -rf "$WORK"
}
trap cleanup EXIT

# --- build helpers -------------------------------------------------------------------------------
gcc -O2 "$HERE/killswitch_agent.c" -o "$AGENT" || die "agent build failed"
cat > "$WORK/hog.c" <<'EOF'
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc,char**argv){
    size_t mb = argc>1 ? (size_t)atoi(argv[1]) : 256;
    for (size_t i=0;i<mb;i++){ char*p=malloc(1<<20); if(!p) return 1; memset(p,1,1<<20); }
    pause(); return 0;   // if we get here, we were NOT oom-killed
}
EOF
gcc -O2 "$WORK/hog.c" -o "$HOG" || die "hog build failed"

# --- delegate controllers ------------------------------------------------------------------------
mkdir -p "$BASE" || die "cannot create $BASE"
# enable controllers for children (root cgroup is exempt from the no-internal-process rule)
echo "+pids +memory" > "$CGROOT/cgroup.subtree_control" 2>/dev/null || true
echo "+pids +memory" > "$BASE/cgroup.subtree_control" 2>/dev/null || true
HAVE_MEM=no; grep -qw memory "$BASE/cgroup.controllers" 2>/dev/null && HAVE_MEM=yes

# read the 8-byte shared counter (long) the agent increments
ctr(){ python3 -c "import struct,sys;print(struct.unpack('q',open('$1','rb').read(8))[0])" 2>/dev/null || echo 0; }
frozen(){ grep -q 'frozen 1' "$1/cgroup.events" 2>/dev/null; }
populated(){ grep -oP 'populated \K[01]' "$1/cgroup.events" 2>/dev/null; }
launch(){ # launch the agent into cgroup $1 with counter $2
  setsid bash -c "echo \$\$ > '$1/cgroup.procs'; exec '$AGENT' '$2' $K" >/dev/null 2>&1 &
  sleep 0.7   # let the tree fill to ~K
}

echo "=================================================================="
echo "A. concurrent-fork termination -- PID enumeration vs cgroup.kill"
echo "=================================================================="

# A1: naive PID-enumeration sweep
CGA="$BASE/naive"; mkdir -p "$CGA"; CNTA="$WORK/ctrA"
launch "$CGA" "$CNTA"
BEFORE_A=$(wc -w < "$CGA/cgroup.procs"); C_AT_A=$(ctr "$CNTA")
mapfile -t SNAP < <(cat "$CGA/cgroup.procs")
for p in "${SNAP[@]}"; do kill -9 "$p" 2>/dev/null; done
sleep 0.5
SURV_A=$(wc -w < "$CGA/cgroup.procs"); POP_A=$(populated "$CGA")
sleep 0.5; C_AFTER_A=$(ctr "$CNTA")
echo "   snapshot killed: ${#SNAP[@]} pids | live before=$BEFORE_A  survivors after sweep=$SURV_A  populated=$POP_A"
echo "   work counter: at_trigger=$C_AT_A  after=$C_AFTER_A  delta_after_trigger=$((C_AFTER_A - C_AT_A))"
echo 1 > "$CGA/cgroup.kill" 2>/dev/null; sleep 0.3

# A2: cgroup.kill on a fresh identical tree
CGB="$BASE/atomic"; mkdir -p "$CGB"; CNTB="$WORK/ctrB"
launch "$CGB" "$CNTB"
BEFORE_B=$(wc -w < "$CGB/cgroup.procs"); C_AT_B=$(ctr "$CNTB")
echo 1 > "$CGB/cgroup.kill"
for i in $(seq 1 200); do [ "$(populated "$CGB")" = 0 ] && break; sleep 0.01; done
SURV_B=$(wc -w < "$CGB/cgroup.procs"); POP_B=$(populated "$CGB")
sleep 0.5; C_AFTER_B=$(ctr "$CNTB")
echo "   cgroup.kill: live before=$BEFORE_B  survivors=$SURV_B  populated=$POP_B"
echo "   work counter: at_trigger=$C_AT_B  after=$C_AFTER_B  delta_after_trigger=$((C_AFTER_B - C_AT_B))"

echo "=================================================================="
echo "B. freeze then inspect -- cgroup.freeze quiesces the tree"
echo "=================================================================="
CGF="$BASE/freeze"; mkdir -p "$CGF"; CNTF="$WORK/ctrF"
launch "$CGF" "$CNTF"
echo 1 > "$CGF/cgroup.freeze"
for i in $(seq 1 200); do frozen "$CGF" && break; sleep 0.01; done
C_FROZEN_1=$(ctr "$CNTF"); PROCS_F=$(wc -w < "$CGF/cgroup.procs"); sleep 0.7; C_FROZEN_2=$(ctr "$CNTF")
echo "   frozen=$(frozen "$CGF" && echo yes || echo no)  inspectable_procs=$PROCS_F"
echo "   work while frozen: t0=$C_FROZEN_1  t0+0.7s=$C_FROZEN_2  advanced=$((C_FROZEN_2 - C_FROZEN_1))  (0 == quiescent)"
echo 0 > "$CGF/cgroup.freeze"; echo 1 > "$CGF/cgroup.kill" 2>/dev/null; sleep 0.3

echo "=================================================================="
echo "C. resource bounds -- pids.max and memory.max"
echo "=================================================================="
CGP="$BASE/pids"; mkdir -p "$CGP"; CNTP="$WORK/ctrP"
echo 20 > "$CGP/pids.max" 2>/dev/null && {
  setsid bash -c "echo \$\$ > '$CGP/cgroup.procs'; exec '$AGENT' '$CNTP' 100" >/dev/null 2>&1 &
  sleep 1.0
  PEAK=$(wc -w < "$CGP/cgroup.procs"); PMAX=$(grep -oP 'max \K[0-9]+' "$CGP/pids.events" 2>/dev/null || echo 0)
  echo "   pids.max=20  peak_procs=$PEAK  pids.events.max(hits)=$PMAX  (peak<=20 == cap holds)"
  echo 1 > "$CGP/cgroup.kill" 2>/dev/null; sleep 0.3
} || echo "   pids controller unavailable, skipped"

if [ "$HAVE_MEM" = yes ]; then
  CGM="$BASE/mem"; mkdir -p "$CGM"
  echo 64M > "$CGM/memory.max" 2>/dev/null
  echo 0   > "$CGM/memory.swap.max" 2>/dev/null || true
  setsid bash -c "echo \$\$ > '$CGM/cgroup.procs'; exec '$HOG' 256" >/dev/null 2>&1 &
  HPID=$!; wait $HPID 2>/dev/null; HRC=$?
  OOM=$(grep -oP 'oom_kill \K[0-9]+' "$CGM/memory.events" 2>/dev/null || echo 0)
  echo "   memory.max=64M  hog_tried=256M  oom_kill_count=$OOM  hog_exit=$HRC  (oom>0 and host alive == contained)"
  echo 1 > "$CGM/cgroup.kill" 2>/dev/null; sleep 0.3
else
  echo "   memory controller not delegated on this host, skipped"
fi

echo "=================================================================="
echo "KILLSWITCH_RESULT pid_enum_survivors=$SURV_A cgroup_kill_survivors=$SURV_B \
kill_post_trigger_writes=$((C_AFTER_B - C_AT_B)) enum_post_trigger_writes=$((C_AFTER_A - C_AT_A)) \
frozen_advance=$((C_FROZEN_2 - C_FROZEN_1))"
echo "=================================================================="
