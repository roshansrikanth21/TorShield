#!/bin/bash
# Stage 12: fragment fix + regression (TCP integrity/ciphertext, UDP nonce).
set -u
cd /home/ts/ts || exit 1
KEY=$(python3 -c 'print("00112233445566778899aabbccddeeff"*2)')
say() { printf '\n=== %s ===\n' "$*"; }
modprobe chacha_x86_64

say "rebuild + load"
make 2>&1 | grep -E 'error|CC \[M\]|LD \[M\]' | tail -3
rmmod torshield 2>/dev/null; insmod ./torshield.ko
./torshieldctl set-key "$KEY" >/dev/null
./torshieldctl add-peer 10.0.0.1; ./torshieldctl add-peer 10.0.0.2
ip netns exec n1 ethtool -K veth1 tso on gso on >/dev/null 2>&1
ip netns exec n2 ethtool -K veth2 tso on gso on >/dev/null 2>&1

say "A) fragmented UDP 4000 B (MTU 1500, DF off)"
ip netns exec n1 link set veth1 mtu 1500; ip netns exec n2 link set veth2 mtu 1500
ip netns exec n2 timeout 12 python3 - <<'PY' >/tmp/f.rx 2>&1 &
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9070)); s.settimeout(8)
try:
    d,_=s.recvfrom(8192)
    exp=bytes(i%251 for i in range(4000))
    print("received=%d match=%s" % (len(d), d==exp))
except Exception as e:
    print("received=0 error=%r" % (e,))
PY
sleep 1
ip netns exec n1 timeout 6 python3 - <<'PY'
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IP,10,0)
s.sendto(bytes(i%251 for i in range(4000)),("10.0.0.2",9070))
PY
sleep 3
cat /tmp/f.rx
echo "stats:"; cat /proc/torshield/stats | tr '\n' ' '; echo

say "B) TCP 512 KB integrity + ciphertext (TSO on)"
rm -f /tmp/t.pcap
ip netns exec n2 timeout 30 tcpdump -i veth2 -s 0 -w /tmp/t.pcap -U "tcp port 9071" 2>/dev/null & CAP=$!
ip netns exec n2 timeout 25 python3 - <<'PY' &
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9071)); s.listen(1); s.settimeout(20)
c,_=s.accept(); buf=bytearray()
while len(buf)<512*1024:
    d=c.recv(1<<20)
    if not d: break
    buf+=d
exp=bytes(i%251 for i in range(512*1024))
print("TCP received=%d correct=%d" % (len(buf), sum(1 for a,b in zip(buf,exp) if a==b)))
c.close()
PY
sleep 1.5
ip netns exec n1 timeout 20 python3 -c "
import socket
c=socket.socket(); c.connect(('10.0.0.2',9071)); c.sendall(bytes(i%251 for i in range(512*1024))); c.shutdown(socket.SHUT_WR); c.close()"
sleep 3
kill $CAP 2>/dev/null; wait $CAP 2>/dev/null
echo "wire:"; python3 pcap.py gso /tmp/t.pcap 9071
python3 pcap.py dump /tmp/t.pcap 9071 | head -3
echo "stats:"; cat /proc/torshield/stats | tr '\n' ' '; echo

say "C) UDP DF nonce regression"
rm -f /tmp/u.pcap
ip netns exec n2 timeout 12 tcpdump -i veth2 -s 0 -w /tmp/u.pcap -U "udp port 9072" 2>/dev/null & CAP=$!
ip netns exec n2 timeout 10 python3 - <<'PY' &
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9072)); s.settimeout(8); n=0
try:
    while n<2: s.recvfrom(4096); n+=1
except Exception: pass
PY
sleep 1.5
ip netns exec n1 timeout 6 python3 - <<'PY'
import socket,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.setsockopt(socket.IPPROTO_IP,10,2)
for ch in (b"A",b"B"): s.sendto(ch*1000,("10.0.0.2",9072)); time.sleep(0.2)
PY
sleep 2
kill $CAP 2>/dev/null; wait $CAP 2>/dev/null
python3 pcap.py udp /tmp/u.pcap 9072
