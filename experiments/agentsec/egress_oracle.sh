#!/usr/bin/env bash
# egress_oracle.sh -- give the network invariant the same grade of oracle the others have.
#
# The filesystem rows in this repo are backed by "the canary file exists". The execution
# rows are backed by the kernel's errno. The egress row was backed by "sendto returned a
# positive number", which is a claim about the sending kernel accepting a buffer and not a
# claim that anything left. This builds the missing half: a receiver in a namespace we own,
# reachable over a real link, that logs the verbatim sentinel of whatever arrives.
#
# Topology, all unprivileged -- one user namespace, two network namespaces inside it:
#
#     [ RX netns ]  10.99.0.1  veth0 <---> veth1  10.99.0.2  [ AGENT netns ]
#       egress_sink (tcp 9000, udp 9001)              egress_agent
#       tcpdump on veth0
#
# Two independent witnesses, because they do not prove the same thing. The sink log says a
# datagram was delivered to a socket we control. The capture says bytes crossed the wire.
# A hand-built raw packet can do the second without the first, so both columns are reported
# and a disagreement is a result rather than noise.
#
# Usage: ./egress_oracle.sh [trials]      (default 20)
set -u

TRIALS="${1:-20}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/out"
RX_IP=10.99.0.1
AG_IP=10.99.0.2
TCP_PORT=9000
UDP_PORT=9001
ARMS="baseline seccomp landlock emptyns"

# ------------------------------------------------------------------ build + re-exec

if [ -z "${EGRESS_INNER:-}" ]; then
    mkdir -p "$OUT"
    gcc -O2 "$HERE/egress_sink.c"  -o "$OUT/egress_sink"  || exit 1
    gcc -O2 "$HERE/egress_tap.c"   -o "$OUT/egress_tap"   || exit 1
    gcc -O2 "$HERE/egress_agent.c" -o "$OUT/egress_agent" -lseccomp || exit 1
    # The whole harness needs CAP_NET_ADMIN and CAP_NET_RAW, which a user namespace grants
    # over its own network namespaces without touching the host's.
    exec env EGRESS_INNER=1 unshare -Urn "$0" "$TRIALS"
fi

SINK_LOG="$OUT/egress_sink.log"
WIRE_LOG="$OUT/egress_wire.log"
AGENT_LOG="$OUT/egress_agent.log"
: > "$SINK_LOG"; : > "$WIRE_LOG"; : > "$AGENT_LOG"

cleanup(){
    [ -n "${TD_PID:-}"   ] && kill "$TD_PID"   2>/dev/null
    [ -n "${SINK_PID:-}" ] && kill "$SINK_PID" 2>/dev/null
    [ -n "${AG_PID:-}"   ] && kill "$AG_PID"   2>/dev/null
    return 0
}
trap cleanup EXIT

# ------------------------------------------------------------------ topology

ip link set lo up

# A parked process is the handle for the agent's network namespace: `ip link set ... netns`
# and `nsenter` both address it by pid, and there is no /var/run/netns to bind-mount into
# without also unsharing the mount namespace.
unshare -n sleep 3600 &
AG_PID=$!
sleep 0.3

ip link add veth0 type veth peer name veth1 || exit 1
ip link set veth1 netns "$AG_PID"           || exit 1
ip addr add "$RX_IP/24" dev veth0
ip link set veth0 up
nsenter -t "$AG_PID" -n ip addr add "$AG_IP/24" dev veth1
nsenter -t "$AG_PID" -n ip link set veth1 up
nsenter -t "$AG_PID" -n ip link set lo up

echo "topology: RX $RX_IP <-> AGENT $AG_IP"

# ------------------------------------------------------------------ witnesses

"$OUT/egress_sink" "$RX_IP" "$TCP_PORT" "$UDP_PORT" >> "$SINK_LOG" 2>&1 &
SINK_PID=$!
for _ in $(seq 40); do grep -q SINK_READY "$SINK_LOG" && break; sleep 0.1; done
grep -q SINK_READY "$SINK_LOG" || { echo "sink never came up"; cat "$SINK_LOG"; exit 1; }

"$OUT/egress_tap" veth0 >> "$WIRE_LOG" 2>&1 &
TD_PID=$!
for _ in $(seq 40); do grep -q TAP_READY "$WIRE_LOG" && break; sleep 0.1; done
grep -q TAP_READY "$WIRE_LOG" || { echo "tap never came up"; cat "$WIRE_LOG"; exit 1; }
sleep 0.5

# ------------------------------------------------------------------ run the arms

for arm in $ARMS; do
    echo "arm $arm"
    for t in $(seq 1 "$TRIALS"); do
        n=$(printf '%02d' "$t")
        if [ "$arm" = emptyns ]; then
            # The control is the namespace, not anything the binary does to itself: a fresh
            # network namespace has a down loopback and no other interface at all.
            unshare -n "$OUT/egress_agent" "$arm" "$RX_IP" "$TCP_PORT" "$UDP_PORT" "$n" \
                >> "$AGENT_LOG" 2>&1
        else
            nsenter -t "$AG_PID" -n "$OUT/egress_agent" "$arm" "$RX_IP" "$TCP_PORT" "$UDP_PORT" "$n" \
                >> "$AGENT_LOG" 2>&1
        fi
    done
done

# Let anything still in flight land before the witnesses are torn down.
sleep 1.5
kill "$TD_PID" 2>/dev/null; wait "$TD_PID" 2>/dev/null
kill "$SINK_PID" 2>/dev/null; wait "$SINK_PID" 2>/dev/null

# ------------------------------------------------------------------ tabulate
#
# Tokens carry (arm, attempt, trial), so attribution is a set membership test and never a
# guess about which trial a late datagram belonged to. Both witnesses render one record per
# line with the sentinel contiguous, so extraction is the same grep against both.

TOK_RE='EGRESS/[a-z]*/[a-z_]*/[0-9][0-9]'
grep -o "$TOK_RE" "$SINK_LOG" | sort -u > "$OUT/egress_tokens_sink.txt"
grep -o "$TOK_RE" "$WIRE_LOG" | sort -u > "$OUT/egress_tokens_wire.txt"

printf '\n%-10s %-12s %10s %10s %10s\n' arm attempt call_ok sink wire
printf '%s\n' "-------------------------------------------------------"
for arm in $ARMS; do
    for att in tcp udp conn_udp raw preconn_tcp; do
        ok=$(grep -c "arm=$arm .*name=$att call=ok" "$AGENT_LOG")
        sk=$(grep -c "^EGRESS/$arm/$att/" "$OUT/egress_tokens_sink.txt")
        wr=$(grep -c "^EGRESS/$arm/$att/" "$OUT/egress_tokens_wire.txt")
        printf '%-10s %-12s %7s/%-2s %7s/%-2s %7s/%-2s\n' \
            "$arm" "$att" "$ok" "$TRIALS" "$sk" "$TRIALS" "$wr" "$TRIALS"
    done
done

echo
echo "preconnect established, by arm:"
for arm in $ARMS; do
    y=$(grep -c "PRECONNECT arm=$arm .*established=yes" "$AGENT_LOG")
    printf '  %-10s %s/%s\n' "$arm" "$y" "$TRIALS"
done

echo
echo "logs: $AGENT_LOG  $SINK_LOG  $WIRE_LOG"
