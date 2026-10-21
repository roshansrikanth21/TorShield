#!/bin/bash
# Stage 1 (runs INSIDE the VM, as root): build, load, configure, basic checks.
set -u
cd /home/ts/ts || exit 1
echo "=== uname ==="; uname -r
echo "=== build ==="
make 2>&1 | tail -5
ls -l torshield.ko torshieldctl || exit 1

echo "=== load ==="
rmmod torshield 2>/dev/null
insmod ./torshield.ko && echo "insmod OK"
dmesg | tail -3
echo "=== proc perms ==="
ls -l /proc/torshield/
echo "=== configure ==="
./torshieldctl set-key 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
./torshieldctl add-peer 10.0.0.1
./torshieldctl add-peer 10.0.0.2
./torshieldctl status
./torshieldctl list-peers
echo "=== netns ==="
ip netns del n1 2>/dev/null; ip netns del n2 2>/dev/null
ip netns add n1; ip netns add n2
ip link add veth1 netns n1 type veth peer name veth2 netns n2
ip -n n1 addr add 10.0.0.1/24 dev veth1
ip -n n2 addr add 10.0.0.2/24 dev veth2
ip -n n1 link set veth1 up; ip -n n2 link set veth2 up
ip -n n1 link set lo up; ip -n n2 link set lo up
sleep 1
echo "=== veth offload features ==="
ip netns exec n1 ethtool -k veth1 2>/dev/null | grep -E '^(tcp-segmentation-offload|generic-segmentation-offload|tx-checksumming|rx-checksumming|scatter-gather):'
echo "=== ping (ICMP untouched) ==="
ip netns exec n1 ping -c1 -W2 10.0.0.2 >/dev/null && echo "ping OK" || echo "ping FAIL"
