#!/bin/bash
# Stage 13: throughput with the corrected datapath (TCG VM: relative numbers only).
set -u
cd /home/ts/ts || exit 1
KEY=$(python3 -c 'print("00112233445566778899aabbccddeeff"*2)')
modprobe chacha_x86_64
ip netns exec n1 ethtool -K veth1 tso on gso on >/dev/null 2>&1
ip netns exec n2 ethtool -K veth2 tso on gso on >/dev/null 2>&1

perf() {  # $1 label
  ip netns exec n2 pkill iperf3 2>/dev/null
  ip netns exec n2 iperf3 -s -1 -D >/dev/null 2>&1
  sleep 1
  ip netns exec n1 iperf3 -c 10.0.0.2 -t 5 -J 2>/dev/null | python3 -c '
import sys,json
d=json.load(sys.stdin)
print("%s: %.1f Mbps, %d retransmits" % (sys.argv[1], d["end"]["sum_received"]["bits_per_second"]/1e6,
      d["end"]["sum_sent"].get("retransmits",-1)))' "$1"
}

rmmod torshield 2>/dev/null
echo "--- module unloaded (baseline) ---"
perf "no-module"

insmod ./torshield.ko
./torshieldctl set-key "$KEY" >/dev/null
./torshieldctl add-peer 10.0.0.1; ./torshieldctl add-peer 10.0.0.2
echo "--- module loaded, encrypted ---"
perf "torshield"
cat /proc/torshield/stats | tr '\n' ' '; echo

echo "--- UDP (iperf3 -u -b 50M), module loaded ---"
ip netns exec n2 iperf3 -s -1 -D >/dev/null 2>&1; sleep 1
ip netns exec n1 iperf3 -c 10.0.0.2 -u -b 50M -t 4 -J 2>/dev/null | python3 -c '
import sys,json
d=json.load(sys.stdin)
print("udp: %.1f Mbps, lost %.2f%%" % (d["end"]["sum"]["bits_per_second"]/1e6, d["end"]["sum"]["lost_percent"]))'
