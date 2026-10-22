#!/bin/bash
# Native (WSL2 kernel 6.18.54.1) smoke test + throughput/latency measurement.
# Builds the module against /root/wsl-kernel, loads it, and compares a direct
# veth path with the TorShield tunnel path.  Run as root.
set -u
SRC=/mnt/k/tor-project/module/LKM
DST=/root/ts
K=/root/wsl-kernel
say() { printf '\n=== %s ===\n' "$*"; }
get() { awk -v k="$1" '$1==k{print $2}' /proc/torshield/stats; }

say "build (KDIR=$K)"
rm -rf "$DST"; mkdir -p "$DST"
cp -a "$SRC/." "$DST/"
cd "$DST" || exit 1
make KDIR="$K" -j8 2>&1 | tail -15
[ -f torshield.ko ] || { echo "FAIL: no ko"; exit 1; }
echo "vermagic: $(modinfo -F vermagic torshield.ko 2>/dev/null || echo unknown)"

say "install + load"
install -D -m 0644 torshield.ko "/lib/modules/$(uname -r)/extra/torshield.ko"
depmod -a
rmmod torshield 2>/dev/null
modprobe torshield; echo "modprobe rc=$?"
[ -r /proc/torshield/mode ] || { echo "FAIL: module not loaded"; exit 1; }
cat /proc/torshield/mode

say "netns + veth (10.0.0.0/24, fd00::/64)"
ip netns del n1 2>/dev/null; ip netns del n2 2>/dev/null
ip netns add n1; ip netns add n2
ip link add veth1 netns n1 type veth peer name veth2 netns n2
ip -n n1 addr add 10.0.0.1/24 dev veth1
ip -n n2 addr add 10.0.0.2/24 dev veth2
ip -n n1 -6 addr add fd00::1/64 dev veth1 nodad
ip -n n2 -6 addr add fd00::2/64 dev veth2 nodad
ip -n n1 link set veth1 up; ip -n n1 link set lo up
ip -n n2 link set veth2 up; ip -n n2 link set lo up
sleep 1
ip netns exec n1 ping -c 1 -W 2 10.0.0.2 >/dev/null && echo "underlay v4 ok"
ip netns exec n1 ping -6 -c 1 -W 2 fd00::2 >/dev/null && echo "underlay v6 ok"

KEY=$(python3 -c 'print("aa"*32)')
./torshieldctl set-key "$KEY" >/dev/null
./torshieldctl clear-peers

run_iperf() { # label
    ip netns exec n2 timeout 30 iperf3 -s -1 -p 5201 >/tmp/iperf-srv.txt 2>&1 &
    SRV=$!
    sleep 0.7
    ip netns exec n1 timeout 25 iperf3 -c 10.0.0.2 -p 5201 -t 8 -P 4 -J >/tmp/iperf.json 2>/tmp/iperf.err
    wait $SRV 2>/dev/null
    python3 - "$1" <<'PY'
import json, sys
d = json.load(open('/tmp/iperf.json'))
e = d['end']
print("%s: sender=%.1f Mbit/s receiver=%.1f Mbit/s retransmits=%d"
      % (sys.argv[1], e['sum_sent']['bits_per_second']/1e6,
         e['sum_received']['bits_per_second']/1e6,
         e['sum_sent'].get('retransmits', -1)))
PY
}

run_ping() { # label
    out=$(ip netns exec n1 ping -c 50 -i 0.02 -W 2 10.0.0.2 2>&1)
    echo "$1: $(echo "$out" | tail -2 | head -1)"
}

say "baseline (module inert, no peers)"
run_iperf "baseline TCP"
run_ping "baseline ping"

say "tunnel mode (netfilter encap, global PSK)"
./torshieldctl add-peer 10.0.0.1 >/dev/null
./torshieldctl add-peer 10.0.0.2 >/dev/null
./torshieldctl list-peers
stat_before=$(get tun_out)
run_iperf "tunnel TCP"
run_ping "tunnel ping"
stat_after=$(get tun_out)
echo "tun_out delta: $((stat_after-stat_before))"

say "v4 UDP echo 256 x 1 KB over the tunnel"
ip netns exec n2 timeout 60 python3 -u - >/tmp/echo4.txt 2>&1 <<'PY' &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.0.0.2", 9430)); s.settimeout(55)
for _ in range(256):
    d, a = s.recvfrom(4096)
    s.sendto(d, a)
print("v4 echo replies: 256")
PY
SRV=$!
sleep 1
ip netns exec n1 timeout 55 python3 -u - <<'PY'
import socket
c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
c.bind(("10.0.0.1", 0)); c.settimeout(3)
ok = 0
for i in range(256):
    m = bytes([i % 251]) * 1024
    c.sendto(m, ("10.0.0.2", 9430))
    d, _ = c.recvfrom(4096)
    ok += (d == m)
print("v4 tunnel echo: %d/256" % ok)
PY
wait $SRV 2>/dev/null
echo "$(cat /tmp/echo4.txt)"

say "v6 UDP echo 64 x 1 KB over the tunnel"
ip netns exec n2 timeout 60 python3 -u - >/tmp/echo6.txt 2>&1 <<'PY' &
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind(("fd00::2", 9431)); s.settimeout(55)
for _ in range(64):
    d, a = s.recvfrom(4096)
    s.sendto(d, a)
print("v6 echo replies: 64")
PY
SRV=$!
sleep 1
ip netns exec n1 timeout 55 python3 -u - <<'PY'
import socket
c = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
c.bind(("fd00::1", 0)); c.settimeout(3)
ok = 0
for i in range(64):
    m = bytes([i % 251]) * 1024
    c.sendto(m, ("fd00::2", 9431))
    d, _ = c.recvfrom(4096)
    ok += (d == m)
print("v6 tunnel echo: %d/64" % ok)
PY
wait $SRV 2>/dev/null
echo "$(cat /tmp/echo6.txt)"

say "stats"
grep -E 'tun_(out|in|rx|drop|replay|acl|roam|rlimit)|dev_' /proc/torshield/stats
echo "DONE"
