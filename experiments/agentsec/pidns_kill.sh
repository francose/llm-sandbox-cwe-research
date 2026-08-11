#!/usr/bin/env bash
# EXP-PIDNS (Part IV, I4): a rootless race-free tree kill.
#
# killswitch.sh needs a writable cgroup, which an unprivileged user is not delegated on every host.
# This is the unprivileged counterpart: put the agent tree in its own PID namespace and kill the
# namespace's init. When init dies the kernel SIGKILLs every remaining process in that namespace
# (pid_namespaces(7)), so there is no snapshot to go stale -- the same race-freedom property
# cgroup.kill has, reachable without root.
#
# Both arms run the SAME tree in the SAME kind of namespace; only the kill mechanism differs:
#   A. enumeration sweep -- snapshot the namespace's members from the host, signal each
#   B. init kill        -- SIGKILL the one host-visible PID that is init inside the namespace
#
# Survivors are counted by PID-namespace inode (/proc/<pid>/ns/pid), not by process name, so the
# count is exact and cannot be confounded by unrelated processes on the host.
#
# The agent is killswitch_agent.c: ~K persistent workers each forking short-lived grandchildren, so
# PIDs churn continuously. That churn is the condition the enumeration race needs; a tree that is not
# forking during teardown is cleared by either method (see EXP_KILLSWITCH_RESULTS.md).
#
# Run: bash pidns_kill.sh          (no privilege; needs unprivileged user namespaces)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d /tmp/pidns_kill.XXXXX)"
AGENT="$WORK/agent"
K="${K:-30}"
TRIALS="${TRIALS:-20}"
SETTLE="${SETTLE:-0.6}"     # let the tree reach full population before triggering
QUIESCE_MAX="${QUIESCE_MAX:-50}"   # x 0.1s poll before declaring a survivor set

die(){ echo "PIDNS_ABORT: $*" >&2; exit 1; }
cleanup(){ pkill -9 -f "$AGENT" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

command -v unshare >/dev/null || die "unshare not present"
gcc -O2 "$HERE/killswitch_agent.c" -o "$AGENT" || die "agent build failed"

# Preflight: unprivileged user + PID namespaces have to actually work here.
unshare -r --pid --fork true 2>/dev/null || die "unprivileged user+pid namespaces unavailable on this host"

# Every host PID currently living in PID-namespace inode $1.
#
# One exec, not one readlink per PID: a per-PID fork loop costs hundreds of milliseconds and would
# charge the enumeration arm for shell overhead rather than for the kernel race we are measuring.
members(){
  local ns="$1"
  ls -l /proc/[0-9]*/ns/pid 2>/dev/null \
    | awk -v ns="$ns" '$NF==ns { n=split($(NF-2),a,"/"); print a[3] }'
}

OURNS="$(readlink /proc/self/ns/pid)"

# Walk down from $1 to the first descendant living in a different PID namespace: that is init
# inside the new one. Walking beats assuming a fixed parent depth -- unshare may or may not fork an
# extra level depending on how the shell started it.
find_init(){
  local p="$1" kid ns
  ns="$(readlink "/proc/$p/ns/pid" 2>/dev/null)" || return 1
  [ -n "$ns" ] && [ "$ns" != "$OURNS" ] && { echo "$p"; return 0; }
  for kid in $(pgrep -P "$p" 2>/dev/null); do
    find_init "$kid" && return 0
  done
  return 1
}

# Start the agent in a fresh user+PID namespace. Echoes "<init_host_pid> <ns_inode>".
start_tree(){
  local ctr="$1"
  : > "$ctr"
  unshare -r --pid --fork "$AGENT" "$ctr" "$K" >/dev/null 2>&1 &
  local upid=$! init="" i
  for i in $(seq 1 60); do
    init="$(find_init "$upid" 2>/dev/null)" && [ -n "$init" ] && break
    sleep 0.05
  done
  [ -n "$init" ] || return 1
  local ns; ns="$(readlink "/proc/$init/ns/pid" 2>/dev/null)"
  [ -n "$ns" ] || return 1
  echo "$init $ns"
}

counter(){ [ -s "$1" ] && od -An -tu8 -N8 "$1" 2>/dev/null | tr -d ' ' || echo 0; }

# Poll until the namespace is empty or we run out of patience. Echoes the final survivor count.
wait_quiesce(){
  local ns="$1" i n
  for i in $(seq 1 "$QUIESCE_MAX"); do
    n="$(members "$ns" | wc -l)"
    [ "$n" = 0 ] && { echo 0; return; }
    sleep 0.1
  done
  members "$ns" | wc -l
}

run_arm(){
  local arm="$1" t residual=0 trials_with_residual=0 imm_total=0 trials_with_imm=0
  local post_total=0 peak=0 ms_total=0
  for t in $(seq 1 "$TRIALS"); do
    local ctr="$WORK/ctr.$arm.$t" started init ns
    started="$(start_tree "$ctr")" || { echo "  trial $t: tree did not start" >&2; continue; }
    init="${started%% *}"; ns="${started##* }"
    sleep "$SETTLE"

    local pop; pop="$(members "$ns" | wc -l)"
    [ "$pop" -gt "$peak" ] && peak="$pop"
    local c_trigger; c_trigger="$(counter "$ctr")"
    local t0; t0=$(date +%s%N)

    if [ "$arm" = enum ]; then
      # Snapshot, then signal each. Anything forked after the snapshot is not on the list.
      local snap; snap="$(members "$ns")"
      for p in $snap; do kill -9 "$p" 2>/dev/null; done
    else
      # Kill init only; the kernel takes the rest of the namespace down with it.
      kill -9 "$init" 2>/dev/null
    fi

    # Alive the instant the kill mechanism returns -- what a supervisor that declares "done" here
    # would still be leaving behind.
    local imm; imm="$(members "$ns" | wc -l)"
    [ "$imm" -gt 0 ] && { imm_total=$(( imm_total + imm )); trials_with_imm=$(( trials_with_imm + 1 )); }

    local left; left="$(wait_quiesce "$ns")"
    local t1; t1=$(date +%s%N)
    ms_total=$(( ms_total + (t1 - t0) / 1000000 ))
    local c_after; c_after="$(counter "$ctr")"
    post_total=$(( post_total + (c_after - c_trigger) ))
    if [ "$left" -gt 0 ]; then
      residual=$(( residual + left ))
      trials_with_residual=$(( trials_with_residual + 1 ))
      # do not leave a survivor set running into the next trial
      for p in $(members "$ns"); do kill -9 "$p" 2>/dev/null; done
    fi
    sleep 0.2
  done
  echo "$arm immediate_survivor_trials=$trials_with_imm/$TRIALS immediate_survivors=$imm_total residual_survivor_trials=$trials_with_residual/$TRIALS residual_survivors=$residual peak_population=$peak post_trigger_work=$post_total mean_trigger_to_zero_ms=$(( ms_total / TRIALS ))"
}

# --- control: the same tree with NO PID namespace ------------------------------------------------
#
# Arm B kills one PID and the whole tree goes down. That could be read two ways: the namespace
# semantics did it, or killing the agent's own supervisor was always enough. This arm settles it --
# same agent, same single kill of the supervisor, no namespace. Membership is by process group
# (one `ps` exec) since there is no namespace inode to key on.
pg_members(){ ps -eo pid=,pgid= 2>/dev/null | awk -v g="$1" '$2==g {print $1}'; }

run_control(){
  local t alive_total=0 trials_alive=0 peak=0
  for t in $(seq 1 "$TRIALS"); do
    local ctr="$WORK/ctr.ctl.$t"
    : > "$ctr"
    setsid "$AGENT" "$ctr" "$K" >/dev/null 2>&1 &
    local sup=$! i pg=""
    for i in $(seq 1 40); do pg="$(ps -o pgid= -p "$sup" 2>/dev/null | tr -d ' ')"; [ -n "$pg" ] && break; sleep 0.05; done
    [ -n "$pg" ] || { echo "  trial $t: control tree did not start" >&2; continue; }
    sleep "$SETTLE"
    local pop; pop="$(pg_members "$pg" | wc -l)"
    [ "$pop" -gt "$peak" ] && peak="$pop"

    kill -9 "$sup" 2>/dev/null       # supervisor only, exactly as in arm B
    sleep 0.5
    local left; left="$(pg_members "$pg" | wc -l)"
    if [ "$left" -gt 0 ]; then
      alive_total=$(( alive_total + left )); trials_alive=$(( trials_alive + 1 ))
      for p in $(pg_members "$pg"); do kill -9 "$p" 2>/dev/null; done
    fi
    sleep 0.2
  done
  echo "control trials_with_survivors=$trials_alive/$TRIALS total_survivors=$alive_total peak_population=$peak"
}

echo "EXP-PIDNS: rootless race-free tree kill (K=$K workers, $TRIALS trials per arm)"
echo "kernel: $(uname -r)"
echo
echo "Arm A -- PID-enumeration sweep (snapshot the namespace, signal each member)"
A="$(run_arm enum)"
echo "  $A"
echo
echo "Arm B -- kill the PID-namespace init (kernel reaps the namespace)"
B="$(run_arm init)"
echo "  $B"
echo
echo "Arm C -- control: same single supervisor kill, NO PID namespace"
C="$(run_control)"
echo "  $C"
echo
echo "PIDNS_RESULT $A | $B | $C"
