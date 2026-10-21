#!/bin/bash
# Stage 21: TC clsact/eBPF egress.
#   - mode=tc: netfilter egress is bypassed, a TC classifier on each underlay
#     redirects inner packets to a per-namespace torshield netdevice
#   - the device encapsulates (AEAD stays in ndo_start_xmit)
#   - outer frames carry TS_TC_MARK and are not redirected again
#   - ingress decapsulation stays on the netfilter LOCAL_IN hook
#
# Inner and outer addresses are deliberately distinct (10.0.0.x/fd00::x vs
# 10.0.1.x/fd01::x) so underlay ARP/NDP can never look like inner traffic.
# Run inside the VM as root from /home/ts/ts.
set -u
cd /home/ts/ts || exit 1
DEBUG=${1:-0}
KEYG=$(python3 -c 'print("aa"*32)')
K=$(python3 -c 'print("cc"*32)')
K6=$(python3 -c 'print("dd"*32)')
TC=/home/ts/ts/tc/torshield-tc
OBJ=/home/ts/ts/tc/torshield_tc.o
say() { printf '\n=== %s ===\n' "$*"; }
stat() { grep -E 'tun_(out|in|rx|drop|replay|peer|acl|roam)|dev_(out|drop)' /proc/torshield/stats | tr '\n' ' '; echo; }
counters() {
    awk '$1 ~ /^(tun_out|tun_in|tun_rx|tun_drop|tun_replay|tun_acl|tun_roam|dev_out|dev_drop)$/ {printf "%s=%s ", $1, $2}' /proc/torshield/stats
    echo
}

say "build + install"
# Drop the previous run's namespaces first: their torshield devices hold the
# module, and a stale module would silently survive rmmod/modprobe.
ip netns del n1 2>/dev/null; ip netns del n2 2>/dev/null
make 2>&1 | grep -E 'error|LD \[M\]' | tail -3
make -C tc 2>&1 | grep -E 'error|warning' | head -5
ls -l tc/torshield_tc.o tc/torshield-tc
rmmod torshield 2>/dev/null
install -D -m 0644 torshield.ko /lib/modules/$(uname -r)/extra/torshield.ko
depmod -a
modprobe torshield; echo "modprobe rc=$?"
echo "$DEBUG" > /sys/module/torshield/parameters/ts_debug 2>/dev/null
./torshieldctl set-key "$KEYG" >/dev/null
echo -n "mode before attach: "; cat /proc/torshield/mode

say "netns + underlay (10.0.1.x / fd01::x) + inner loopbacks (10.0.0.x / fd00::x)"
ip netns add n1; ip netns add n2
ip link add veth1 netns n1 type veth peer name veth2 netns n2
ip -n n1 addr add 10.0.1.1/24 dev veth1
ip -n n2 addr add 10.0.1.2/24 dev veth2
ip -n n1 -6 addr add fd01::1/64 dev veth1 nodad
ip -n n2 -6 addr add fd01::2/64 dev veth2 nodad
ip -n n1 addr add 10.0.0.1/32 dev lo
ip -n n2 addr add 10.0.0.2/32 dev lo
ip -n n1 -6 addr add fd00::1/128 dev lo nodad
ip -n n2 -6 addr add fd00::2/128 dev lo nodad
ip -n n1 link set veth1 up; ip -n n2 link set veth2 up
ip -n n1 link set lo up; ip -n n2 link set lo up
sleep 1
ip -n n1 route add 10.0.0.0/24 via 10.0.1.2 dev veth1
ip -n n2 route add 10.0.0.0/24 via 10.0.1.1 dev veth2
ip -n n1 -6 route add fd00::/64 via fd01::2 dev veth1
ip -n n2 -6 route add fd00::/64 via fd01::1 dev veth2
echo "n1 routes:"; ip -n n1 route | grep 10.0.0; ip -n n1 -6 route | grep fd00
echo "n2 routes:"; ip -n n2 route | grep 10.0.0; ip -n n2 -6 route | grep fd00

say "peer config (inner prefixes allowed; endpoints are the underlay addresses)"
./torshieldctl clear-peers
./torshieldctl add-peer 10.0.1.2 key "$K" allowed 10.0.0.1/32,10.0.0.2/32
./torshieldctl add-peer fd01::2 key "$K6" allowed fd00::1/128,fd00::2/128
./torshieldctl list-peers

say "torshield devices + TC classifier on both ends"
ip -n n1 link add name ts0 link veth1 type torshield; echo "n1 dev rc=$?"
ip netns exec n1 sh -c 'echo 1 > /proc/sys/net/ipv6/conf/ts0/disable_ipv6' 2>/dev/null
ip -n n1 link set ts0 up
ip -n n2 link add name ts1 link veth2 type torshield; echo "n2 dev rc=$?"
ip netns exec n2 sh -c 'echo 1 > /proc/sys/net/ipv6/conf/ts1/disable_ipv6' 2>/dev/null
ip -n n2 link set ts1 up
ip netns exec n1 "$TC" attach -o "$OBJ" -i veth1 -d ts0 \
    -4 10.0.0.1/32 -4 10.0.0.2/32 \
    -6 fd00::1/128 -6 fd00::2/128 || exit 1
ip netns exec n2 "$TC" attach -o "$OBJ" -i veth2 -d ts1 \
    -4 10.0.0.1/32 -4 10.0.0.2/32 \
    -6 fd00::1/128 -6 fd00::2/128 || exit 1
echo -n "mode after attach: "; cat /proc/torshield/mode
ip netns exec n1 tc filter show dev veth1 egress | head -4

echo -n "before: "; counters

say "1) IPv4 UDP echo (256 KB) over the TC path"
rm -f /tmp/t21a.pcap /tmp/r21a.txt
ip netns exec n2 timeout 90 tcpdump -Q in -i veth2 -s 0 -w /tmp/t21a.pcap -U "udp port 4789" 2>/dev/null & CAP=$!
ip netns exec n2 timeout 80 python3 -u - > /tmp/r21a.txt 2>&1 <<'PY' &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("10.0.0.2", 9410)); s.settimeout(70)
for i in range(256):
    d, a = s.recvfrom(4096)
    s.sendto(d, a)
print("v4 echo server: 256 replies sent")
PY
SRV=$!
sleep 1.5
ip netns exec n1 timeout 70 python3 -u - <<'PY'
import socket
c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
c.bind(("10.0.0.1", 0)); c.settimeout(5)
ok = 0
for i in range(256):
    msg = bytes([i % 251]) * 1024
    c.sendto(msg, ("10.0.0.2", 9410))
    d, _ = c.recvfrom(4096)
    ok += (d == msg)
print("v4 TC UDP echo: %d/256 round trips correct (%d bytes)"
      % (ok, ok * 1024))
PY
wait $SRV 2>/dev/null
kill $CAP 2>/dev/null; wait $CAP 2>/dev/null
echo "server: $(cat /tmp/r21a.txt)"
echo -n "after v4: "; counters

say "2) IPv6 UDP echo (64 KB) over the TC path"
rm -f /tmp/r21a6.txt /tmp/t21b.pcap
ip netns exec n2 timeout 100 tcpdump -Q in -i veth2 -s 0 -w /tmp/t21b.pcap -U "udp port 4789" 2>/dev/null & CAP6=$!
ip netns exec n2 timeout 100 python3 -u - > /tmp/r21a6.txt 2>&1 <<'PY' &
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("fd00::2", 9411)); s.settimeout(90)
n = 0
while True:
    try:
        d, a = s.recvfrom(4096)
    except Exception:
        break
    if d[4:8] == b"DONE":
        break
    s.sendto(d, a)
    n += 1
print("v6 echo server: %d replies sent" % n)
PY
SRV=$!
sleep 1.5
ip netns exec n1 timeout 90 python3 -u - <<'PY'
import socket, struct
c = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
c.bind(("fd00::1", 0)); c.settimeout(2)

def roundtrip(tag, payload, tries=5):
    msg = struct.pack("!I", tag) + payload
    for k in range(tries):
        c.sendto(msg, ("fd00::2", 9411))
        try:
            while True:
                d, _ = c.recvfrom(4096)
                if d[:4] == msg[:4]:
                    return (d == msg), k
        except socket.timeout:
            continue
    return False, tries

for i in range(3):
    roundtrip(0xF0000000 + i, b"warmup")
ok = retries = 0
for i in range(64):
    good, k = roundtrip(i, bytes([i % 251]) * 1024)
    ok += good
    retries += k
c.sendto(struct.pack("!I", 0xDEAD0000) + b"DONE", ("fd00::2", 9411))
print("v6 TC UDP echo: %d/64 round trips correct (%d bytes) retries=%d"
      % (ok, ok * 1024, retries))
PY
wait $SRV 2>/dev/null
kill $CAP6 2>/dev/null; wait $CAP6 2>/dev/null
echo "server: $(cat /tmp/r21a6.txt)"
echo -n "after v6: "; counters

say "3) path evidence: every encapsulated packet came through the device"
ip -n n1 -s link show ts0 | tail -3
ip -n n2 -s link show ts1 | tail -3
TO=$(awk '$1=="tun_out"{print $2}' /proc/torshield/stats)
DO=$(awk '$1=="dev_out"{print $2}' /proc/torshield/stats)
DD=$(awk '$1=="dev_drop"{print $2}' /proc/torshield/stats)
TD=$(awk '$1=="tun_drop"{print $2}' /proc/torshield/stats)
echo "tun_out=$TO dev_out=$DO tun_drop=$TD dev_drop=$DD"
if [ "$DO" -gt 0 ] && [ "$TO" = 0 ] && [ "$DD" = 0 ] && [ "$TD" = 0 ]; then
    echo "PASS: TC redirected inner packets; netfilter encapsulated nothing"
else
    echo "FAIL: dev_out=$DO tun_out=$TO (netfilter path taken or device path dead)"
fi

say "4) detach falls back to the netfilter tunnel path"
ip netns exec n1 "$TC" detach -i veth1 || echo "detach n1 rc=$?"
ip netns exec n2 "$TC" detach -i veth2 || echo "detach n2 rc=$?"
echo -n "mode after detach: "; cat /proc/torshield/mode
ip netns exec n2 timeout 30 python3 -u - > /tmp/r21d.txt 2>&1 <<'PY' &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.0.0.2", 9412)); s.settimeout(25)
n = 0
while n < 16:
    d, a = s.recvfrom(4096)
    s.sendto(d, a)
    n += 1
print("fallback echo server: %d replies" % n)
PY
SRV=$!
sleep 1.5
ip netns exec n1 timeout 25 python3 -u - <<'PY'
import socket
c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
c.bind(("10.0.0.1", 0)); c.settimeout(3)
ok = 0
for i in range(16):
    m = b"F" * 512
    c.sendto(m, ("10.0.0.2", 9412))
    d, _ = c.recvfrom(4096)
    ok += (d == m)
print("fallback netfilter echo: %d/16 correct" % ok)
PY
wait $SRV 2>/dev/null
echo "server: $(cat /tmp/r21d.txt)"
echo -n "after detach: "; counters
echo "dmesg:"
dmesg | grep 'torshield:' | tail -24
echo "DONE"
