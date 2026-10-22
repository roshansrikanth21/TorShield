#!/bin/bash
# Native throughput series (3 runs each) on the final module.
set -u
SRC=/mnt/k/tor-project/module/LKM
DST=/root/ts
K=/root/wsl-kernel
cd "$DST" || exit 1
# assume the module was built by the previous stage; rebuild to be sure
make KDIR="$K" -j8 >/tmp/b.log 2>&1 || { tail -20 /tmp/b.log; exit 1; }
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

bench() { # label streams port
    ip netns exec n2 timeout 40 iperf3 -s -1 -p "$3" >/tmp/bs.txt 2>&1 & S=$!
    sleep 0.7
    ip netns exec n1 timeout 35 iperf3 -c 10.0.0.2 -p "$3" -t 6 -P "$2" -J >/tmp/b.json 2>/tmp/b.err
    wait $S 2>/dev/null
    python3 - "$1" <<'PY'
import json, sys
d = json.load(open('/tmp/b.json')); e = d['end']
print("%-26s %8.1f Mbit/s (sender) %8.1f Mbit/s (receiver) retr=%d"
      % (sys.argv[1], e['sum_sent']['bits_per_second']/1e6,
         e['sum_received']['bits_per_second']/1e6,
         e['sum_sent'].get('retransmits', -1)))
PY
}

echo "=== baseline: direct veth, no peers ==="
for i in 1 2 3; do bench "baseline 4-stream #$i" 4 5301; done

echo "=== tunnel: netfilter encap + AEAD ==="
./torshieldctl add-peer 10.0.0.1 >/dev/null
./torshieldctl add-peer 10.0.0.2 >/dev/null
for i in 1 2 3; do bench "tunnel 1-stream #$i" 1 5311; done
for i in 1 2 3; do bench "tunnel 4-stream #$i" 4 5321; done

echo "=== ping RTT (100 packets) ==="
ip netns exec n1 ping -c 100 -i 0.01 -W 2 10.0.0.2 | tail -1
echo "=== stats ==="
grep -E 'tun_(out|in|rx|drop|replay|rlimit)|dev_' /proc/torshield/stats
