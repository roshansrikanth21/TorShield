#!/bin/bash
# Stage 24: fail-closed TC guard.
#
# Verifies that deleting the egress classifier (or its clsact qdisc) while
# /proc/torshield/mode is still "tc" drops peer-destined packets at the
# LOCAL_OUT/FORWARD guard, instead of leaking them in clear.  Then restores
# the classifier and verifies the normal TC path still works.
set -u
cd /home/ts/ts || exit 1
KEYG=$(python3 -c 'print("aa"*32)')
K=$(python3 -c 'print("cc"*32)')
K6=$(python3 -c 'print("dd"*32)')
TC=/home/ts/ts/tc/torshield-tc
OBJ=/home/ts/ts/tc/torshield_tc.o
say() { printf '\n=== %s ===\n' "$*"; }
counters() {
    awk '$1 ~ /^(tun_out|tun_in|tun_rx|tun_drop|tun_replay|tun_acl|tun_roam|dev_out|dev_drop|tc_guard)$/ {printf "%s=%s ", $1, $2}' /proc/torshield/stats
    echo
}
getc() { awk -v k="$1" '$1==k {print $2}' /proc/torshield/stats; }

say "build + install"
ip netns del n1 2>/dev/null; ip netns del n2 2>/dev/null
make 2>&1 | grep -E 'error|LD \[M\]' | tail -3
make -C tc 2>&1 | grep -E 'error|warning' | head -5
rmmod torshield 2>/dev/null
install -D -m 0644 torshield.ko /lib/modules/$(uname -r)/extra/torshield.ko
depmod -a
modprobe torshield; echo "modprobe rc=$?"
./torshieldctl set-key "$KEYG" >/dev/null
echo -n "mode: "; cat /proc/torshield/mode

say "netns + underlay + inner addresses"
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

say "peers + torshield devices + TC classifier"
./torshieldctl clear-peers
./torshieldctl add-peer 10.0.1.2 key "$K" allowed 10.0.0.1/32,10.0.0.2/32
./torshieldctl add-peer fd01::2 key "$K6" allowed fd00::1/128,fd00::2/128
ip -n n1 link add name ts0 link veth1 type torshield
ip netns exec n1 sh -c 'echo 1 > /proc/sys/net/ipv6/conf/ts0/disable_ipv6' 2>/dev/null
ip -n n1 link set ts0 up
ip -n n2 link add name ts1 link veth2 type torshield
ip netns exec n2 sh -c 'echo 1 > /proc/sys/net/ipv6/conf/ts1/disable_ipv6' 2>/dev/null
ip -n n2 link set ts1 up
# No -4/-6 here: the loader must read the peer prefixes from
# /proc/torshield/peers and fill the maps by itself.
ip netns exec n1 "$TC" attach -o "$OBJ" -i veth1 -d ts0 || exit 1
ip netns exec n2 "$TC" attach -o "$OBJ" -i veth2 -d ts1 \
    -4 10.0.0.1/32 -4 10.0.0.2/32 \
    -6 fd00::1/128 -6 fd00::2/128 || exit 1

say "1) baseline: TC echo works"
ip netns exec n2 timeout 30 python3 -u - > /tmp/r24base.txt 2>&1 <<'PY' &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.0.0.2", 9420)); s.settimeout(25)
n = 0
while n < 16:
    d, a = s.recvfrom(4096)
    s.sendto(d, a)
    n += 1
print("baseline server: %d replies" % n)
PY
SRV=$!
sleep 1
ip netns exec n1 timeout 25 python3 -u - <<'PY'
import socket
c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
c.bind(("10.0.0.1", 0)); c.settimeout(3)
ok = 0
for i in range(16):
    m = b"B" * 256
    c.sendto(m, ("10.0.0.2", 9420))
    d, _ = c.recvfrom(4096)
    ok += (d == m)
print("baseline client: %d/16" % ok)
PY
wait $SRV 2>/dev/null
cat /tmp/r24base.txt
echo -n "after baseline: "; counters

say "2) delete the egress classifier on n1 while mode=tc"
G0=$(getc tc_guard); D0=$(getc dev_out); T0=$(getc tun_out)
ip netns exec n1 tc filter del dev veth1 egress
echo "filters left:"; ip netns exec n1 tc filter show dev veth1 egress
ip netns exec n2 timeout 10 python3 -u - > /tmp/r24leak.txt 2>&1 <<'PY' &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.0.0.2", 9421)); s.settimeout(6)
n = 0
try:
    while n < 8:
        d, a = s.recvfrom(4096)
        n += 1
        s.sendto(d, a)
except Exception:
    pass
print("leak server received: %d" % n)
PY
SRV=$!
sleep 1
ip netns exec n1 timeout 8 python3 -u - > /tmp/r24client.txt 2>&1 <<'PY'
import socket, time
c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
c.bind(("10.0.0.1", 0)); c.settimeout(1)
sent = blocked = 0
for i in range(8):
    try:
        c.sendto(b"LEAK" * 8, ("10.0.0.2", 9421))
        sent += 1
    except OSError:
        blocked += 1
    time.sleep(0.05)
print("classifier-removed client: sent=%d blocked=%d" % (sent, blocked))
PY
wait $SRV 2>/dev/null
cat /tmp/r24client.txt /tmp/r24leak.txt
G1=$(getc tc_guard); D1=$(getc dev_out); T1=$(getc tun_out)
echo "tc_guard delta=$((G1-G0)) dev_out delta=$((D1-D0)) tun_out delta=$((T1-T0))"
LEAK=$(sed -n 's/.*received: \([0-9]*\).*/\1/p' /tmp/r24leak.txt)
[ -z "$LEAK" ] && LEAK=-1
BLOCKED=$(sed -n 's/.*blocked=\([0-9]*\).*/\1/p' /tmp/r24client.txt)
[ -z "$BLOCKED" ] && BLOCKED=0
if [ "$LEAK" = 0 ] && [ "$BLOCKED" -ge 1 ] && [ $((G1-G0)) -ge 1 ] && [ "$D1" = "$D0" ] && [ "$T1" = "$T0" ]; then
    echo "PASS: classifier removal fails closed (sendto blocked, no clear delivery)"
else
    echo "FAIL: leak=$LEAK blocked=$BLOCKED guard=$((G1-G0)) dev=$((D1-D0)) tun=$((T1-T0))"
fi

say "3) delete the clsact qdisc on n1 while mode=tc"
ip netns exec n1 tc qdisc del dev veth1 clsact
G0=$(getc tc_guard); D0=$(getc dev_out); T0=$(getc tun_out)
ip netns exec n2 timeout 10 python3 -u - > /tmp/r24leak2.txt 2>&1 <<'PY' &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.0.0.2", 9422)); s.settimeout(6)
n = 0
try:
    while n < 8:
        d, a = s.recvfrom(4096)
        n += 1
        s.sendto(d, a)
except Exception:
    pass
print("qdisc-removed server received: %d" % n)
PY
SRV=$!
sleep 1
ip netns exec n1 timeout 8 python3 -u - > /tmp/r24client2.txt 2>&1 <<'PY'
import socket, time
c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
c.bind(("10.0.0.1", 0)); c.settimeout(1)
sent = blocked = 0
for i in range(8):
    try:
        c.sendto(b"LEAK" * 8, ("10.0.0.2", 9422))
        sent += 1
    except OSError:
        blocked += 1
    time.sleep(0.05)
print("qdisc-removed client: sent=%d blocked=%d" % (sent, blocked))
PY
wait $SRV 2>/dev/null
cat /tmp/r24client2.txt /tmp/r24leak2.txt
G1=$(getc tc_guard); D1=$(getc dev_out); T1=$(getc tun_out)
echo "tc_guard delta=$((G1-G0)) dev_out delta=$((D1-D0)) tun_out delta=$((T1-T0))"
LEAK=$(sed -n 's/.*received: \([0-9]*\).*/\1/p' /tmp/r24leak2.txt)
[ -z "$LEAK" ] && LEAK=-1
BLOCKED=$(sed -n 's/.*blocked=\([0-9]*\).*/\1/p' /tmp/r24client2.txt)
[ -z "$BLOCKED" ] && BLOCKED=0
if [ "$LEAK" = 0 ] && [ "$BLOCKED" -ge 1 ] && [ $((G1-G0)) -ge 1 ] && [ "$D1" = "$D0" ] && [ "$T1" = "$T0" ]; then
    echo "PASS: qdisc removal fails closed (no clear delivery, guard drops)"
else
    echo "FAIL: leak=$LEAK blocked=$BLOCKED guard=$((G1-G0)) dev=$((D1-D0)) tun=$((T1-T0))"
fi

say "4) restore the classifier and verify traffic again"
ip netns exec n1 "$TC" attach -o "$OBJ" -i veth1 -d ts0 \
    -4 10.0.0.1/32 -4 10.0.0.2/32 \
    -6 fd00::1/128 -6 fd00::2/128 || exit 1
ip netns exec n2 timeout 30 python3 -u - > /tmp/r24restore.txt 2>&1 <<'PY' &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.0.0.2", 9423)); s.settimeout(25)
n = 0
while n < 16:
    d, a = s.recvfrom(4096)
    s.sendto(d, a)
    n += 1
print("restore server: %d replies" % n)
PY
SRV=$!
sleep 1
ip netns exec n1 timeout 25 python3 -u - <<'PY'
import socket
c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
c.bind(("10.0.0.1", 0)); c.settimeout(3)
ok = 0
for i in range(16):
    m = b"R" * 256
    c.sendto(m, ("10.0.0.2", 9423))
    d, _ = c.recvfrom(4096)
    ok += (d == m)
print("restore client: %d/16" % ok)
PY
wait $SRV 2>/dev/null
cat /tmp/r24restore.txt
echo -n "after restore: "; counters

say "5) restore tunnel mode and check the netfilter fallback"
ip netns exec n1 "$TC" detach -i veth1
ip netns exec n2 "$TC" detach -i veth2
echo -n "mode: "; cat /proc/torshield/mode
ip netns exec n2 timeout 20 python3 -u - > /tmp/r24tun.txt 2>&1 <<'PY' &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.0.0.2", 9424)); s.settimeout(15)
n = 0
while n < 8:
    d, a = s.recvfrom(4096)
    s.sendto(d, a)
    n += 1
print("tunnel server: %d replies" % n)
PY
SRV=$!
sleep 1
ip netns exec n1 timeout 15 python3 -u - <<'PY'
import socket
c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
c.bind(("10.0.0.1", 0)); c.settimeout(3)
ok = 0
for i in range(8):
    m = b"T" * 256
    c.sendto(m, ("10.0.0.2", 9424))
    d, _ = c.recvfrom(4096)
    ok += (d == m)
print("tunnel client: %d/8" % ok)
PY
wait $SRV 2>/dev/null
cat /tmp/r24tun.txt
echo -n "final: "; counters

say "6) peer-list change invalidates tc mode"
echo tc > /proc/torshield/mode
./torshieldctl add-peer 10.0.9.9 key "$K" >/dev/null 2>&1
M_ADD=$(cat /proc/torshield/mode)
echo tc > /proc/torshield/mode
./torshieldctl del-peer 10.0.9.9 >/dev/null 2>&1
M_DEL=$(cat /proc/torshield/mode)
echo tc > /proc/torshield/mode
./torshieldctl clear-peers >/dev/null 2>&1
M_CLEAR=$(cat /proc/torshield/mode)
echo "mode after add=$M_ADD del=$M_DEL clear=$M_CLEAR"
if [ "$M_ADD" = tunnel ] && [ "$M_DEL" = tunnel ] && [ "$M_CLEAR" = tunnel ]; then
    echo "PASS: peer add/del/clear forced tunnel mode (stale TC maps cannot be used)"
else
    echo "FAIL: add=$M_ADD del=$M_DEL clear=$M_CLEAR"
fi

echo "dmesg:"; dmesg | grep 'torshield:' | tail -12
echo "DONE"
