#!/bin/bash
# Stage 22: pre-AEAD per-source rate limiter (ts_rl_pps).
#
# Sends tunnel-framed garbage from one source and compares tun_drop (packets
# that reached Poly1305) with the limiter off and on.  With ts_rl_pps=50 and
# 1000 packets, most must be stopped by tun_rlimit instead of tun_drop.
# Run as root from /home/ts/ts (or the native source dir).
set -u
cd "$(dirname "$0")" || exit 1
KF=${KDIR:-/lib/modules/$(uname -r)/build}
RL=/sys/module/torshield/parameters/ts_rl_pps
say() { printf '\n=== %s ===\n' "$*"; }
get() { awk -v k="$1" '$1==k{print $2}' /proc/torshield/stats; }
snap() { echo "rx=$(get tun_rx) drop=$(get tun_drop) rlimit=$(get tun_rlimit) in=$(get tun_in)"; }

say "build + install (KDIR=$KF)"
ip netns del n1 2>/dev/null; ip netns del n2 2>/dev/null
rmmod torshield 2>/dev/null
make KDIR="$KF" 2>&1 | grep -E 'error|warning:|\bLD \[M\]' | tail -5
install -D -m 0644 torshield.ko "/lib/modules/$(uname -r)/extra/torshield.ko"
depmod -a
modprobe torshield; echo "modprobe rc=$?"
[ -e "$RL" ] || { echo "FAIL: $RL missing"; exit 1; }

say "netns + veth (10.0.0.0/24)"
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

send500() {
    ip netns exec n1 timeout 30 python3 -u - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.0.0.1", 0))
# 16-byte tunnel header (magic/version) + 16-byte "ciphertext" + 16-byte tag;
# enough to pass the framing check and reach the Poly1305 step.
pkt = b"TS\x01" + b"\x00" * 13 + b"\x00" * 16 + b"\x00" * 16
for _ in range(1000):
    s.sendto(pkt, ("10.0.0.2", 4789))
print("sent 1000 tunnel-framed packets")
PY
}

say "1) limiter off (ts_rl_pps=0): every packet reaches the AEAD"
echo 0 > "$RL"
b_rx=$(get tun_rx); b_drop=$(get tun_drop); b_rl=$(get tun_rlimit)
send500
sleep 1
rx=$(get tun_rx); drop=$(get tun_drop); rl=$(get tun_rlimit)
drx=$((rx-b_rx)); ddrop=$((drop-b_drop)); drl=$((rl-b_rl))
echo "delta: tun_rx=$drx tun_drop=$ddrop tun_rlimit=$drl"
if [ "$drl" -eq 0 ] && [ "$ddrop" -ge 900 ]; then
    echo "PASS: with the limiter off all 1000 reach the AEAD"
else
    echo "FAIL: expected rlimit=0, drop>=900"
fi

say "2) limiter 50 pps: most packets must stop at tun_rlimit"
echo 50 > "$RL"
b_rx=$(get tun_rx); b_drop=$(get tun_drop); b_rl=$(get tun_rlimit)
send500
sleep 1
rx=$(get tun_rx); drop=$(get tun_drop); rl=$(get tun_rlimit)
drx=$((rx-b_rx)); ddrop=$((drop-b_drop)); drl=$((rl-b_rl))
echo "delta: tun_rx=$drx tun_drop=$ddrop tun_rlimit=$drl"
if [ "$drl" -ge 300 ] && [ "$ddrop" -le 250 ] && [ "$drx" -ge 900 ]; then
    echo "PASS: limiter stopped $drl/1000 before the AEAD; only $ddrop reached it"
else
    echo "FAIL: expected rlimit>=300, drop<=250, rx>=900"
fi

say "3) limiter still allows a legitimate tunnel echo at 1000 pps"
echo 1000 > "$RL"
ip netns exec n2 timeout 30 python3 -u - >/tmp/r22.txt 2>&1 <<'PY' &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.0.0.2", 9422)); s.settimeout(25)
for _ in range(64):
    d, a = s.recvfrom(4096)
    s.sendto(d, a)
print("echo replies: 64")
PY
SRV=$!
sleep 1
ip netns exec n1 timeout 25 python3 -u - <<'PY'
import socket
c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
c.bind(("10.0.0.1", 0)); c.settimeout(3)
ok = 0
for i in range(64):
    m = b"R" * 512
    c.sendto(m, ("10.0.0.2", 9422))
    d, _ = c.recvfrom(4096)
    ok += (d == m)
print("legit echo: %d/64" % ok)
PY
wait $SRV 2>/dev/null
echo "server: $(cat /tmp/r22.txt)"
echo "final: $(snap)"

say "cleanup"
echo 0 > "$RL"
ip netns del n1; ip netns del n2
