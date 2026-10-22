#!/bin/bash
# Sustained tunnel stress with memory accounting (one WSL invocation).
set -u
cd /root/ts || exit 1
make KDIR=/root/wsl-kernel -j8 >/tmp/b.log 2>&1 || { tail -20 /tmp/b.log; exit 1; }
install -D -m 0644 torshield.ko "/lib/modules/$(uname -r)/extra/torshield.ko"
depmod -a; rmmod torshield 2>/dev/null; modprobe torshield || exit 1
ip netns del n1 2>/dev/null; ip netns del n2 2>/dev/null
ip netns add n1; ip netns add n2
ip link add veth1 netns n1 type veth peer name veth2 netns n2
ip -n n1 addr add 10.0.0.1/24 dev veth1
ip -n n2 addr add 10.0.0.2/24 dev veth2
ip -n n1 link set veth1 up; ip -n n1 link set lo up
ip -n n2 link set veth2 up; ip -n n2 link set lo up
./torshieldctl set-key "$(python3 -c 'print("aa"*32)')" >/dev/null
./torshieldctl clear-peers
./torshieldctl add-peer 10.0.0.1 >/dev/null
./torshieldctl add-peer 10.0.0.2 >/dev/null
mem() { awk '/^(MemFree|MemAvailable|Slab|SUnreclaim|SReclaimable):/{printf "%s=%s%s ",$1,$2,$3}' /proc/meminfo; echo; }
echo "before: $(mem)"
( for i in $(seq 1 20); do sleep 2; echo "t=${i}x2s: $(mem)"; done ) & MON=$!
ip netns exec n2 timeout 60 iperf3 -s -1 -p 5601 >/tmp/ts.txt 2>&1 & S=$!
sleep 0.7
ip netns exec n1 timeout 55 iperf3 -c 10.0.0.2 -p 5601 -t 30 -P 4 | grep -E 'SUM.*receiver' | tail -1
wait $S 2>/dev/null
kill $MON 2>/dev/null
echo "after: $(mem)"
echo "uptime: $(uptime -p)"
grep -E 'tun_(out|in|rx|drop|replay|rlimit)|dev_' /proc/torshield/stats
