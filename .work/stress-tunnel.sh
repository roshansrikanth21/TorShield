#!/bin/bash
# Tunnel stress with live dmesg capture (root, one WSL invocation).
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
rm -f /mnt/k/tor-project/.work/dmesg-live.txt
dmesg -w | stdbuf -oL tee /mnt/k/tor-project/.work/dmesg-live.txt >/dev/null & DL=$!
for i in 1 2 3; do
  ip netns exec n2 timeout 40 iperf3 -s -1 -p 550$i >/tmp/ts.txt 2>&1 & S=$!
  sleep 0.7
  echo "--- run $i ---"
  ip netns exec n1 timeout 35 iperf3 -c 10.0.0.2 -p 550$i -t 6 -P 4 | grep -E 'SUM.*receiver' | tail -1
  wait $S 2>/dev/null
done
echo "--- long run 30s ---"
ip netns exec n2 timeout 60 iperf3 -s -1 -p 5510 >/tmp/ts.txt 2>&1 & S=$!
sleep 0.7
ip netns exec n1 timeout 55 iperf3 -c 10.0.0.2 -p 5510 -t 30 -P 4 | grep -E 'SUM.*receiver' | tail -1
wait $S 2>/dev/null
kill $DL 2>/dev/null
echo "survived; stats:"
grep -E 'tun_(out|in|rx|drop|replay|rlimit)' /proc/torshield/stats
