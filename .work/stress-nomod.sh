#!/bin/bash
# Reproduce the bench baseline without the module, snapshotting dmesg.
set -u
rmmod torshield 2>/dev/null
( while :; do dmesg | tail -80 > /mnt/k/tor-project/.work/dmesg-nomod.txt 2>/dev/null; sleep 0.5; done ) & SNAP=$!
ip netns del n1 2>/dev/null; ip netns del n2 2>/dev/null
ip netns add n1; ip netns add n2
ip link add veth1 netns n1 type veth peer name veth2 netns n2
ip -n n1 addr add 10.0.0.1/24 dev veth1
ip -n n2 addr add 10.0.0.2/24 dev veth2
ip -n n1 link set veth1 up; ip -n n1 link set lo up
ip -n n2 link set veth2 up; ip -n n2 link set lo up
for i in 1 2 3; do
  ip netns exec n2 timeout 40 iperf3 -s -1 -p 540$i >/tmp/ns.txt 2>&1 & S=$!
  sleep 0.7
  ip netns exec n1 timeout 35 iperf3 -c 10.0.0.2 -p 540$i -t 6 -P 4 | grep -E 'SUM.*receiver' | tail -1
  wait $S 2>/dev/null
done
kill $SNAP 2>/dev/null
echo "baseline-nomod done; uptime: $(uptime -p)"
