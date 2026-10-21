#!/bin/bash
# Stage 20: cryptokey routing.
#   - per-peer keys (different from the global PSK) and non-zero key ids
#   - allowed inner prefixes (ingress ACL)
#   - distinct inner/outer addressing (endpoint != inner destination)
#   - endpoint roaming after authenticated traffic from a new address
# Run inside the VM as root from /home/ts/ts.
set -u
cd /home/ts/ts || exit 1
KEYG=$(python3 -c 'print("aa"*32)')
K=$(python3 -c 'print("cc"*32)')
K2=$(python3 -c 'print("ee"*32)')
K6=$(python3 -c 'print("dd"*32)')
say() { printf '\n=== %s ===\n' "$*"; }
stat() { grep -E 'tun_(out|in|rx|drop|replay|peer|acl|roam)' /proc/torshield/stats | tr '\n' ' '; echo; }

say "build + install"
make 2>&1 | grep -E 'error|LD \[M\]' | tail -3
rmmod torshield 2>/dev/null
install -D -m 0644 torshield.ko /lib/modules/$(uname -r)/extra/torshield.ko
depmod -a
modprobe torshield; echo "modprobe rc=$?"
./torshieldctl set-key "$KEYG" >/dev/null

say "netns"
ip netns del n1 2>/dev/null; ip netns del n2 2>/dev/null
ip netns add n1; ip netns add n2
ip link add veth1 netns n1 type veth peer name veth2 netns n2
ip -n n1 addr add 10.0.0.1/24 dev veth1
ip -n n2 addr add 10.0.0.2/24 dev veth2
ip -n n1 addr add fd00::1/64 dev veth1 nodad 2>/dev/null
ip -n n2 addr add fd00::2/64 dev veth2 nodad 2>/dev/null
ip -n n1 link set veth1 up; ip -n n2 link set veth2 up
ip -n n1 link set lo up; ip -n n2 link set lo up
sleep 1
MAC2=$(ip netns exec n2 cat /sys/class/net/veth2/address)
echo "veth2 mac: $MAC2"

say "1) per-peer key/id, one link, both directions (shared key K)"
./torshieldctl clear-peers
# The VM kernel holds one peer table and plays both ends.  A single entry
# models the link; its endpoint follows the last authenticated sender, so the
# reply is routed back correctly.  Both inner addresses are allowed.
./torshieldctl add-peer 10.0.0.2 key "$K" allowed 10.0.0.1/32,10.0.0.2/32
./torshieldctl add-peer fd00::2 key "$K6" allowed fd00::1/128,fd00::2/128
echo "peers:"; ./torshieldctl list-peers

rm -f /tmp/t20a.pcap /tmp/r20a.txt
ip netns exec n2 timeout 90 tcpdump -Q in -i veth2 -s 0 -w /tmp/t20a.pcap -U "udp port 4789" 2>/dev/null & CAP=$!
ip netns exec n2 timeout 80 python3 -u - > /tmp/r20a.txt 2>&1 <<'PY' &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 9410)); s.settimeout(70)
for i in range(256):
    d, a = s.recvfrom(4096)
    s.sendto(d, a)
print("v4 echo server: 256 replies sent")
PY
SRV=$!
sleep 1.5
ip netns exec n1 timeout 70 python3 -u - <<'PY'
import socket
c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); c.settimeout(5)
ok = 0
for i in range(256):
    msg = bytes([i % 251]) * 1024
    c.sendto(msg, ("10.0.0.2", 9410))
    d, _ = c.recvfrom(4096)
    ok += (d == msg)
print("v4 per-peer-key UDP echo: %d/256 round trips correct (%d bytes)"
      % (ok, ok * 1024))
PY
wait $SRV 2>/dev/null
kill $CAP 2>/dev/null; wait $CAP 2>/dev/null
echo "server: $(cat /tmp/r20a.txt)"
echo -n "stats: "; stat

say "2) IPv6 UDP echo (64 KB) with a per-peer key"
rm -f /tmp/t20a6.txt
ip netns exec n2 timeout 100 python3 -u - > /tmp/t20a6.txt 2>&1 <<'PY' &
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("::", 9411)); s.settimeout(90)
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
c = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); c.settimeout(2)

def roundtrip(tag, payload, tries=5):
    """Send one datagram, return (matched, retries).  Absorbs the first-packet
    loss that neighbour discovery can cause, and ignores stale duplicates."""
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
print("v6 per-peer-key UDP echo: %d/64 round trips correct (%d bytes) retries=%d"
      % (ok, ok * 1024, retries))
PY
wait $SRV 2>/dev/null
echo "server: $(cat /tmp/t20a6.txt)"
echo -n "stats: "; stat

say "3) a single peer with its own key K2 (different from K and the global PSK)"
./torshieldctl clear-peers
./torshieldctl add-peer 10.0.0.2 key "$K2" allowed 10.0.0.0/24
./torshieldctl list-peers
rm -f /tmp/t20b.pcap /tmp/r20b.txt
ip netns exec n2 timeout 20 tcpdump -Q in -i veth2 -s 0 -w /tmp/t20b.pcap -U "udp port 4789" 2>/dev/null & CAP=$!
ip netns exec n2 timeout 15 python3 -u - > /tmp/r20b.txt 2>&1 <<'PY' &
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9412)); s.settimeout(10)
try:
    d,_=s.recvfrom(4096); print("RX %r" % d, flush=True)
except Exception as e:
    print("RX none (%s)" % e, flush=True)
PY
sleep 1.5
ip netns exec n1 timeout 8 python3 -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.sendto(b'PEERKEY-K2',('10.0.0.2',9412))"
sleep 2
kill $CAP 2>/dev/null; wait $CAP 2>/dev/null
echo "receiver: $(cat /tmp/r20b.txt)"
echo -n "stats: "; stat

say "4) allowed-prefix ACL: inner source .1 accepted, .99 dropped"
./torshieldctl clear-peers
./torshieldctl add-peer 10.0.0.1 key "$K" allowed 10.0.0.1/32
rm -f /tmp/r20c.txt
ip netns exec n2 timeout 20 python3 -u - > /tmp/r20c.txt 2>&1 <<'PY' &
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9413)); s.settimeout(12)
while True:
    try:
        d,_=s.recvfrom(4096)
    except Exception:
        break
    print("RX %r" % d, flush=True)
PY
sleep 1.5
echo -n "before: "; stat
ip netns exec n1 python3 inject2.py veth1 "$MAC2" 10.0.0.88 10.0.0.2 "$K" 700001 10.0.0.1 10.0.0.2 9999 9413 ACL-OK
sleep 1
echo -n "after allowed source: "; stat
ip netns exec n1 python3 inject2.py veth1 "$MAC2" 10.0.0.88 10.0.0.2 "$K" 700002 10.0.0.99 10.0.0.2 9999 9413 ACL-SPOOFED
sleep 2
echo -n "after disallowed source: "; stat
echo "receiver:"; cat /tmp/r20c.txt

say "5) distinct inner/outer addressing: inner .2 is reached via outer .99"
ip -n n2 addr add 10.0.0.99/32 dev veth2
./torshieldctl clear-peers
./torshieldctl add-peer 10.0.0.99 key "$K2" allowed 10.0.0.0/24
./torshieldctl list-peers
rm -f /tmp/t20d.pcap /tmp/r20d.txt
ip netns exec n2 timeout 20 tcpdump -Q in -i veth2 -s 0 -w /tmp/t20d.pcap -U "udp port 4789" 2>/dev/null & CAP=$!
ip netns exec n2 timeout 15 python3 -u - > /tmp/r20d.txt 2>&1 <<'PY' &
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9414)); s.settimeout(10)
try:
    d,_=s.recvfrom(4096); print("RX %r" % d, flush=True)
except Exception as e:
    print("RX none (%s)" % e, flush=True)
PY
sleep 1.5
ip netns exec n1 timeout 8 python3 -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.sendto(b'SPLIT-PATH',('10.0.0.2',9414))"
sleep 2
kill $CAP 2>/dev/null; wait $CAP 2>/dev/null
echo "receiver: $(cat /tmp/r20d.txt)"
echo "outer frame (dst should be 10.0.0.99, inner 10.0.0.1 -> 10.0.0.2):"
ip netns exec n2 python3 outeraddr.py /tmp/t20d.pcap 4789
echo -n "stats: "; stat

say "6) endpoint roaming: authenticated packet from 10.0.0.88 moves the endpoint"
ip -n n1 addr add 10.0.0.88/32 dev veth1
./torshieldctl clear-peers
./torshieldctl add-peer 10.0.0.1 key "$K" allowed 10.0.0.0/24
./torshieldctl list-peers
rm -f /tmp/r20e.txt /tmp/r20f.txt /tmp/t20e.pcap
ip netns exec n2 timeout 25 python3 -u - > /tmp/r20e.txt 2>&1 <<'PY' &
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9415)); s.settimeout(15)
try:
    d,_=s.recvfrom(4096); print("RX %r" % d, flush=True)
except Exception as e:
    print("RX none (%s)" % e, flush=True)
PY
sleep 1
ip netns exec n1 python3 inject2.py veth1 "$MAC2" 10.0.0.88 10.0.0.2 "$K" 1 10.0.0.1 10.0.0.2 9999 9415 ROAM
sleep 2
echo "receiver on n2: $(cat /tmp/r20e.txt)"
echo "peers after roam:"; ./torshieldctl list-peers
echo -n "stats after roam: "; stat
echo "(note: both ends share one peer entry in this harness, so the first"
echo " kernel egress seq=1 collides with the injected seq=1 and is dropped"
echo " as a replay; the next datagram seq=2 is the one that gets delivered.)"

ip netns exec n1 timeout 20 tcpdump -Q in -i veth1 -s 0 -w /tmp/t20e.pcap -U "udp port 4789" 2>/dev/null & CAP=$!
ip netns exec n1 timeout 15 python3 -u - > /tmp/r20f.txt 2>&1 <<'PY' &
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("10.0.0.1",9416)); s.settimeout(10)
try:
    d,_=s.recvfrom(4096); print("RX %r" % d, flush=True)
except Exception as e:
    print("RX none (%s)" % e, flush=True)
PY
sleep 1.5
ip netns exec n2 timeout 8 python3 -c "
import socket, time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(('10.0.0.2',0))
s.sendto(b'ROAMED-1',('10.0.0.1',9416))
time.sleep(0.3)
s.sendto(b'ROAMED-2',('10.0.0.1',9416))"
sleep 2
kill $CAP 2>/dev/null; wait $CAP 2>/dev/null
echo "receiver on n1: $(cat /tmp/r20f.txt)"
echo "outer frame on n1 ingress (dst should be 10.0.0.88):"
ip netns exec n1 python3 outeraddr.py /tmp/t20e.pcap 4789
echo -n "stats: "; stat

say "7) tampered packet with a per-peer key -> drop"
ip netns exec n1 python3 inject2.py veth1 "$MAC2" 10.0.0.88 10.0.0.2 "$K" 800002 10.0.0.1 10.0.0.2 9999 9415 TAMPER tamper
sleep 2
echo -n "stats: "; stat

say "final stats"
cat /proc/torshield/stats
say "kernel log"
dmesg | grep -iE 'oops|BUG:|WARNING:|general protection|panic|torshield' | tail -12 || true
echo DONE
