#!/bin/bash
# Native RTT + replay-window check; everything in one WSL invocation.
set -u
SRC=/mnt/k/tor-project/module/LKM
DST=/root/ts
K=/root/wsl-kernel
get() { awk -v k="$1" '$1==k{print $2}' /proc/torshield/stats; }
say() { printf '\n=== %s ===\n' "$*"; }

say "build + load"
rm -rf "$DST"; mkdir -p "$DST"; cp -a "$SRC/." "$DST/"
cd "$DST" || exit 1
make KDIR="$K" -j8 >/tmp/build.log 2>&1 || { tail -20 /tmp/build.log; exit 1; }
install -D -m 0644 torshield.ko "/lib/modules/$(uname -r)/extra/torshield.ko"
depmod -a; rmmod torshield 2>/dev/null; modprobe torshield || exit 1

say "netns + veth"
ip netns del n1 2>/dev/null; ip netns del n2 2>/dev/null
ip netns add n1; ip netns add n2
ip link add veth1 netns n1 type veth peer name veth2 netns n2
ip -n n1 addr add 10.0.0.1/24 dev veth1
ip -n n2 addr add 10.0.0.2/24 dev veth2
ip -n n1 link set veth1 up; ip -n n1 link set lo up
ip -n n2 link set veth2 up; ip -n n2 link set lo up
./torshieldctl set-key "$(python3 -c 'print("aa"*32)')" >/dev/null
./torshieldctl clear-peers

say "RTT baseline (no peers)"
ip netns exec n1 ping -c 100 -i 0.01 -W 2 10.0.0.2 | tail -1
ip netns exec n1 ping -c 100 -i 0.01 -W 2 10.0.0.2 | tail -2 | head -1

say "RTT tunnel (peers set)"
./torshieldctl add-peer 10.0.0.1 >/dev/null
./torshieldctl add-peer 10.0.0.2 >/dev/null
ip netns exec n1 ping -c 100 -i 0.01 -W 2 10.0.0.2 | tail -1
ip netns exec n1 ping -c 100 -i 0.01 -W 2 10.0.0.2 | tail -2 | head -1

say "single-stream TCP + replay delta"
b=$(get tun_replay)
ip netns exec n2 timeout 30 iperf3 -s -1 -p 5202 >/tmp/s1.txt 2>&1 & S=$!
sleep 0.7
ip netns exec n1 timeout 25 iperf3 -c 10.0.0.2 -p 5202 -t 8 -P 1 | grep -E 'sender|receiver' | tail -2
wait $S 2>/dev/null
a=$(get tun_replay); echo "tun_replay delta (1 stream): $((a-b))"

say "four-stream TCP + replay delta"
b=$(get tun_replay)
ip netns exec n2 timeout 30 iperf3 -s -1 -p 5203 >/tmp/s4.txt 2>&1 & S=$!
sleep 0.7
ip netns exec n1 timeout 25 iperf3 -c 10.0.0.2 -p 5203 -t 8 -P 4 | grep -E 'SUM.*sender|SUM.*receiver' | tail -2
wait $S 2>/dev/null
a=$(get tun_replay); echo "tun_replay delta (4 streams): $((a-b))"

say "stats"
grep -E 'tun_(out|in|rx|drop|replay|rlimit)|dev_' /proc/torshield/stats
