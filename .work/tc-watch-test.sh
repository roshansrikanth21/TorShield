#!/bin/bash
set -u
M=/tmp/tsmode
TC=/root/ts/tc/torshield-tc
OBJ=/root/ts/tc/torshield_tc.o
ip netns del w1 2>/dev/null
mkdir -p /var/run/netns
ip netns add w1 || exit 1
ip link add wv0 type veth peer name wv1 || exit 1
ip link set wv1 netns w1
ip link set wv0 up
ip -n w1 link set wv1 up
ip -n w1 link set lo up
echo tunnel > "$M"

echo "=== attach (mode file: $M) ==="
ip netns exec w1 "$TC" attach -o "$OBJ" -i wv1 -d lo \
    -4 10.9.9.1/32 -6 fd99::1/128 -m "$M" || exit 1
echo "mode after attach: $(cat "$M")"
ip netns exec w1 tc filter show dev wv1 egress | head -2

echo "=== start watch (200 ms) ==="
ip netns exec w1 "$TC" watch -i wv1 -m "$M" -n 200 -x >/tmp/watch.log 2>&1 &
WPID=$!
sleep 0.5
echo "watch running: $(kill -0 $WPID 2>/dev/null && echo yes || echo no)"

echo "=== delete the qdisc externally ==="
ip netns exec w1 tc qdisc del dev wv1 clsact 2>&1
sleep 1.2
echo "mode after qdisc del: $(cat "$M")"
echo "--- watch log ---"
cat /tmp/watch.log
wait $WPID; echo "watch rc=$?"

echo "=== cleanup ==="
ip netns del w1
ip link del wv0 2>/dev/null
