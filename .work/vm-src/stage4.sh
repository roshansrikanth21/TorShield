#!/bin/bash
# Stage 4: with counters + fragment/ihl fixes.
#   A) verify build + load
#   B) bulk TCP: how many packets does the module actually see/encrypt/skip?
#   C) fragments: no longer corrupted (fail open)
set -u
cd /home/ts/ts || exit 1
KEY=$(python3 -c 'print("00112233445566778899aabbccddeeff"*2)')
say() { printf '\n=== %s ===\n' "$*"; }

say "build"
make 2>&1 | grep -E 'error|warning|CC \[M\]|LD \[M\]' | tail -5
modprobe chacha_x86_64
rmmod torshield 2>/dev/null; insmod ./torshield.ko || exit 1
./torshieldctl set-key "$KEY" >/dev/null
./torshieldctl add-peer 10.0.0.1
./torshieldctl add-peer 10.0.0.2
cat /proc/torshield/stats

say "T5b bulk TCP, GSO state now recorded"
ip netns exec n1 ethtool -K veth1 tso off gso off >/dev/null 2>&1
ip netns exec n2 ethtool -K veth2 tso off gso off >/dev/null 2>&1
ip netns exec n2 timeout 25 python3 - <<'PY' &
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9005)); s.listen(1); s.settimeout(20)
c,_=s.accept(); n=0
while n < 4*1024*1024:
    d=c.recv(1<<20)
    if not d: break
    n+=len(d)
open("/tmp/t5b.rx","w").write(str(n)); c.close()
PY
sleep 1
ip netns exec n1 timeout 20 python3 - <<'PY'
import socket
c=socket.socket(); c.connect(("10.0.0.2",9005))
buf=b"A"*(1<<20)
for _ in range(4): c.sendall(buf)
c.shutdown(socket.SHUT_WR); c.close()
PY
sleep 2
echo "receiver_bytes=$(cat /tmp/t5b.rx 2>/dev/null)"
echo "--- stats after 4 MB TCP (TSO off) ---"; cat /proc/torshield/stats

say "T5c same, TSO ON"
ip netns exec n1 ethtool -K veth1 tso on gso on >/dev/null 2>&1
ip netns exec n2 ethtool -K veth2 tso on gso on >/dev/null 2>&1
ip netns exec n2 timeout 25 python3 - <<'PY' &
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9006)); s.listen(1); s.settimeout(20)
c,_=s.accept(); n=0
while n < 4*1024*1024:
    d=c.recv(1<<20)
    if not d: break
    n+=len(d)
open("/tmp/t5c.rx","w").write(str(n)); c.close()
PY
sleep 1
ip netns exec n1 timeout 20 python3 - <<'PY'
import socket
c=socket.socket(); c.connect(("10.0.0.2",9006))
buf=b"A"*(1<<20)
for _ in range(4): c.sendall(buf)
c.shutdown(socket.SHUT_WR); c.close()
PY
sleep 2
echo "receiver_bytes=$(cat /tmp/t5c.rx 2>/dev/null)"
echo "--- stats after second 4 MB TCP (TSO on) ---"; cat /proc/torshield/stats

say "T4b fragments: integrity after fail-open fix"
rm -f /tmp/t4b.pcap
ip netns exec n2 timeout 15 tcpdump -i veth2 -s 0 -w /tmp/t4b.pcap -U "ip" 2>/dev/null &
CAP=$!; sleep 1.5
ip netns exec n2 timeout 10 python3 - <<'PY' >/tmp/t4b.rx 2>&1 &
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9003)); s.settimeout(8)
try:
    d,_=s.recvfrom(8192)
    print("received=%d expected=4000 match=%s" % (len(d), d==b"F"*4000))
except Exception as e:
    print("received=0 error=%r" % (e,))
PY
sleep 1
ip netns exec n1 timeout 6 python3 - <<'PY'
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IP, 10, 0)
s.sendto(b"F"*4000, ("10.0.0.2", 9003))
PY
sleep 3
kill $CAP 2>/dev/null; wait $CAP 2>/dev/null
cat /tmp/t4b.rx
python3 pcap.py ipids /tmp/t4b.pcap | head -5
echo "--- final stats ---"; cat /proc/torshield/stats
