#!/bin/bash
# Stage 23: manual rekey with a grace period.
#   - capture the *egress* key id before and after rekey
#   - the previous key is accepted on ingress until "commit"
#   - after commit the old key id is rejected as non-peer
#   - negative command cases do not change state
# Run as root from /home/ts/ts with KDIR set for native builds.
set -u
cd /home/ts/ts || exit 1
KEYG=$(python3 -c 'print("aa"*32)')
K=$(python3 -c 'print("cc"*32)')
K2=$(python3 -c 'print("ee"*32)')
K3=$(python3 -c 'print("ab"*32)')
say() { printf '\n=== %s ===\n' "$*"; }
stat() { grep -E 'tun_(out|in|rx|drop|replay|peer|acl|roam)' /proc/torshield/stats | tr '\n' ' '; echo; }
get() { awk -v k="$1" '$1==k{print $2}' /proc/torshield/stats; }
keyid() { ./torshieldctl list-peers | sed -n 's/.*key=\([0-9][0-9]*\).*/\1/p' | head -1; }

say "build + install"
# Force a rebuild and release old namespaces before unloading: a stale module
# must never make this test pass or fail for the wrong reason.
ip netns del n1 2>/dev/null; ip netns del n2 2>/dev/null
touch torshield.c
make 2>&1 | grep -E 'error|LD \[M\]' | tail -3
if ! rmmod torshield 2>/dev/null; then
    if lsmod | grep -q '^torshield'; then
        echo "FAIL: cannot unload the old torshield module"
        exit 1
    fi
fi
install -D -m 0644 torshield.ko "/lib/modules/$(uname -r)/extra/torshield.ko"
depmod -a
modprobe torshield; echo "modprobe rc=$?"
if [ ! -e /proc/torshield/rekey ]; then
    echo "FAIL: loaded module has no /proc/torshield/rekey"
    lsmod | grep torshield
    exit 1
fi
./torshieldctl set-key "$KEYG" >/dev/null

say "netns + peer"
ip netns add n1; ip netns add n2
ip link add veth1 netns n1 type veth peer name veth2 netns n2
ip -n n1 addr add 10.0.0.1/24 dev veth1
ip -n n2 addr add 10.0.0.2/24 dev veth2
ip -n n1 link set veth1 up; ip -n n1 link set lo up
ip -n n2 link set veth2 up; ip -n n2 link set lo up
sleep 1
MAC2=$(ip netns exec n2 cat /sys/class/net/veth2/address)
./torshieldctl clear-peers
# Remote endpoint 10.0.0.2 for the first request.  Authenticated traffic from
# 10.0.0.1 then roams the endpoint, which is what the reply uses.
./torshieldctl add-peer 10.0.0.2 key "$K" allowed 10.0.0.1/32,10.0.0.2/32
KID_K=$(keyid)
./torshieldctl list-peers
echo "MAC2=$MAC2 KID_K=$KID_K"

say "1) egress key before rekey (n1 -> n2 echo; capture n2 reply)"
rm -f /tmp/r23echo.txt /tmp/k_before.txt /tmp/k_before.err
ip netns exec n2 timeout 25 python3 -u - > /tmp/r23echo.txt 2>&1 <<'PY' &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 9421)); s.settimeout(15)
d, a = s.recvfrom(4096)
s.sendto(d, a)
print("echo reply sent for %r" % d)
PY
ECHO=$!
ip netns exec n2 timeout 10 python3 sniff_key.py veth2 10.0.0.1 8 > /tmp/k_before.txt 2>/tmp/k_before.err &
CAP=$!
sleep 0.5
ip netns exec n1 timeout 10 python3 -u - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
s.sendto(b"EGRESS-REQ", ("10.0.0.2", 9421))
d, _ = s.recvfrom(4096)
print("request reply %r" % d)
PY
wait $CAP 2>/dev/null
wait $ECHO 2>/dev/null
echo "echo server: $(cat /tmp/r23echo.txt)"
echo "egress before raw=$(cat /tmp/k_before.txt 2>/dev/null) expected=$KID_K"
stat

say "2) rotate to K2 (K becomes previous)"
# The echo above leaves the endpoint at 10.0.0.2 again (the reply roams it back).
./torshieldctl rekey-peer 10.0.0.2 "$K2"; echo "rekey rc=$?"
KID_K2=$(keyid)
./torshieldctl list-peers
echo "KID_K2=$KID_K2"
./torshieldctl rekey-peer 10.0.0.2 "$K3" >/dev/null 2>&1; busy_rc=$?
busy_key=$(keyid)
busy_prev=$(./torshieldctl list-peers | grep -c "prev=$KID_K")
echo "second rekey before commit rc=$busy_rc (expect nonzero), key=$busy_key prev=$busy_prev"

say "2b) trigger a roamed endpoint with a normal packet (n1 -> n2)"
rm -f /tmp/r23trig.txt
ip netns exec n2 timeout 20 python3 -u - > /tmp/r23trig.txt 2>&1 <<'PY' &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 9423)); s.settimeout(10)
d, _ = s.recvfrom(4096)
print("trigger received: %s" % d.decode(errors="replace"))
PY
TRIG=$!
sleep 0.5
ip netns exec n1 python3 -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b"EGRESS-TRIGGER",("10.0.0.2",9423))'
wait $TRIG 2>/dev/null
echo "trigger sink: $(cat /tmp/r23trig.txt)"
./torshieldctl list-peers

say "3) egress key after rekey (n2 -> n1; capture n2 egress)"
rm -f /tmp/n1sink.txt /tmp/k_after.txt /tmp/k_after.err
ip netns exec n1 timeout 30 python3 -u - > /tmp/n1sink.txt 2>&1 <<'PY' &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 9422)); s.settimeout(15)
d, _ = s.recvfrom(4096)
print("received 1: %s" % d.decode(errors="replace"))
PY
SINK=$!
ip netns exec n2 timeout 10 python3 sniff_key.py veth2 10.0.0.1 8 > /tmp/k_after.txt 2>/tmp/k_after.err &
CAP2=$!
sleep 0.5
ip netns exec n2 python3 -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b"EGRESS-NEW",("10.0.0.1",9422))'
wait $CAP2 2>/dev/null
wait $SINK 2>/dev/null
echo "n1 sink: $(cat /tmp/n1sink.txt)"
echo "egress after raw=$(cat /tmp/k_after.txt 2>/dev/null) expected=$KID_K2"
stat

say "4) grace accepts old and new; commit rejects old"
rm -f /tmp/r23.txt
ip netns exec n2 timeout 40 python3 -u - > /tmp/r23.txt 2>&1 <<'PY' &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 9420)); s.settimeout(25)
got = []
while len(got) < 6:
    try:
        d, _ = s.recvfrom(4096)
    except Exception:
        break
    got.append(d.decode(errors="replace"))
print("received %d: %s" % (len(got), ",".join(got)))
PY
SRV=$!
sleep 1
before_in=$(get tun_in); before_rx=$(get tun_rx); before_drop=$(get tun_drop)
before_peer=$(get tun_peer); before_replay=$(get tun_replay)
ip netns exec n1 python3 inject2.py veth1 "$MAC2" 10.0.0.1 10.0.0.2 "$K" 900001 10.0.0.1 10.0.0.2 9999 9420 OLD-1
sleep 0.3
ip netns exec n1 python3 inject2.py veth1 "$MAC2" 10.0.0.1 10.0.0.2 "$K" 900002 10.0.0.1 10.0.0.2 9999 9420 OLD-2
sleep 0.3
ip netns exec n1 python3 inject2.py veth1 "$MAC2" 10.0.0.1 10.0.0.2 "$K2" 900003 10.0.0.1 10.0.0.2 9999 9420 NEW-1
sleep 0.3
./torshieldctl rekey-commit 10.0.0.1; echo "commit rc=$?"
./torshieldctl list-peers
ip netns exec n1 python3 inject2.py veth1 "$MAC2" 10.0.0.1 10.0.0.2 "$K" 900004 10.0.0.1 10.0.0.2 9999 9420 OLD-3
sleep 0.3
ip netns exec n1 python3 inject2.py veth1 "$MAC2" 10.0.0.1 10.0.0.2 "$K2" 900005 10.0.0.1 10.0.0.2 9999 9420 NEW-2
sleep 1

say "5) negative rekey edge cases (no state change)"
./torshieldctl rekey-peer 10.0.0.1 "$K2" >/dev/null; same_rc=$?
./torshieldctl rekey-commit 10.0.0.1 >/dev/null 2>&1; noprev_rc=$?
./torshieldctl rekey-peer 10.0.0.1 zz >/dev/null 2>&1; bad_rc=$?
echo "same-key rc=$same_rc (expect 0), commit-without-prev rc=$noprev_rc (expect nonzero), bad-key rc=$bad_rc (expect nonzero)"
./torshieldctl list-peers
wait $SRV 2>/dev/null
cat /tmp/r23.txt

after_in=$(get tun_in); after_rx=$(get tun_rx); after_drop=$(get tun_drop)
after_peer=$(get tun_peer); after_replay=$(get tun_replay)
echo "delta: tun_in=$((after_in-before_in)) tun_rx=$((after_rx-before_rx)) tun_drop=$((after_drop-before_drop)) tun_peer=$((after_peer-before_peer)) tun_replay=$((after_replay-before_replay))"
stat

recv=$(grep -o 'received [0-9]*' /tmp/r23.txt | awk '{print $2}')
n1recv=$(grep -o 'received [0-9]*' /tmp/n1sink.txt | awk '{print $2}')
egress_before=$(awk '{print $1}' /tmp/k_before.txt 2>/dev/null)
egress_after=$(awk '{print $1}' /tmp/k_after.txt 2>/dev/null)
if [ "$recv" = "4" ] && [ "$n1recv" = "1" ] && \
   [ $((after_in-before_in)) -eq 4 ] && [ $((after_rx-before_rx)) -eq 5 ] && \
   [ $((after_peer-before_peer)) -eq 1 ] && \
   [ $((after_drop-before_drop)) -eq 0 ] && \
   [ $((after_replay-before_replay)) -eq 0 ] && \
   [ "$egress_before" = "$KID_K" ] && [ "$egress_after" = "$KID_K2" ] && \
   [ "$busy_rc" != "0" ] && [ "$busy_key" = "$KID_K2" ] && [ "$busy_prev" = "1" ] && \
   [ "$same_rc" = "0" ] && [ "$noprev_rc" != "0" ] && [ "$bad_rc" != "0" ]; then
    echo "PASS: egress switched K->K2; old key accepted before commit, rejected as non-peer after; new key accepted; edge cases exact"
else
    echo "FAIL: recv=$recv n1recv=$n1recv in_delta=$((after_in-before_in)) rx_delta=$((after_rx-before_rx)) peer_delta=$((after_peer-before_peer)) drop_delta=$((after_drop-before_drop)) replay_delta=$((after_replay-before_replay)) egress=$egress_before/$KID_K -> $egress_after/$KID_K2 busy=$busy_rc/$busy_key/$busy_prev same=$same_rc noprev=$noprev_rc bad=$bad_rc"
fi
