#!/bin/bash
# Final acceptance run: the exact repo source, rebuilt and exercised end-to-end.
set -u
cd /home/ts/ts || exit 1
KEY=$(python3 -c 'print("00112233445566778899aabbccddeeff"*2)')
say() { printf '\n=== %s ===\n' "$*"; }

say "build from repo source"
make clean >/dev/null 2>&1; make 2>&1 | grep -E 'error|warning: [^t]|LD \[M\]' | tail -4
ls -l torshield.ko

say "load via modprobe (softdep)"
rmmod torshield 2>/dev/null
install -D -m 0644 torshield.ko /lib/modules/$(uname -r)/extra/torshield.ko; depmod -a
modprobe torshield; echo "modprobe rc=$?"
./torshieldctl set-key "$KEY" >/dev/null
./torshieldctl add-peer 10.0.0.1; ./torshieldctl add-peer 10.0.0.2
./torshieldctl add-peer fd00::1; ./torshieldctl add-peer fd00::2

say "1) TCP 1 MB (v4, TSO on): integrity + ciphertext"
rm -f /tmp/a.pcap
ip netns exec n2 timeout 40 tcpdump -i veth2 -s 0 -w /tmp/a.pcap -U "tcp port 9100" 2>/dev/null & CAP=$!
ip netns exec n2 timeout 30 python3 - <<'PY' &
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9100)); s.listen(1); s.settimeout(25)
c,_=s.accept(); buf=bytearray()
while len(buf)<1024*1024:
    d=c.recv(1<<20)
    if not d: break
    buf+=d
exp=bytes(i%251 for i in range(1024*1024))
print("v4 TCP received=%d correct=%d (%.2f%%)" % (len(buf),sum(1 for a,b in zip(buf,exp) if a==b),100.0*sum(1 for a,b in zip(buf,exp) if a==b)/len(exp)))
c.close()
PY
sleep 1.5
ip netns exec n1 timeout 25 python3 -c "
import socket
c=socket.socket(); c.connect(('10.0.0.2',9100)); c.sendall(bytes(i%251 for i in range(1024*1024))); c.shutdown(socket.SHUT_WR); c.close()"
sleep 3
kill $CAP 2>/dev/null; wait $CAP 2>/dev/null
python3 pcap.py gso /tmp/a.pcap 9100
python3 pcap.py dump /tmp/a.pcap 9100 | head -2

say "2) UDP nonce (v4, DF) + content"
rm -f /tmp/b.pcap
ip netns exec n2 timeout 12 tcpdump -i veth2 -s 0 -w /tmp/b.pcap -U "udp port 9101" 2>/dev/null & CAP=$!
ip netns exec n2 timeout 10 python3 - <<'PY' &
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9101)); s.settimeout(8); got=[]
try:
    while len(got)<2: got.append(s.recvfrom(4096)[0])
except Exception: pass
print("udp content_ok=%s" % (got==[b"A"*1000,b"B"*1000]))
PY
sleep 1.5
ip netns exec n1 timeout 6 python3 - <<'PY'
import socket,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.setsockopt(socket.IPPROTO_IP,10,2)
for ch in (b"A",b"B"): s.sendto(ch*1000,("10.0.0.2",9101)); time.sleep(0.2)
PY
sleep 2
kill $CAP 2>/dev/null; wait $CAP 2>/dev/null
python3 pcap.py udp /tmp/b.pcap 9101

say "3) fragmented UDP (4000 B, MTU 1500)"
ip netns exec n2 timeout 12 python3 - <<'PY' >/tmp/f.rx 2>&1 &
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9102)); s.settimeout(8)
try:
    d,_=s.recvfrom(8192); exp=bytes(i%251 for i in range(4000))
    print("frag received=%d match=%s" % (len(d), d==exp))
except Exception as e: print("frag received=0 err=%r" % (e,))
PY
sleep 1
ip netns exec n1 timeout 6 python3 - <<'PY'
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.setsockopt(socket.IPPROTO_IP,10,0)
s.sendto(bytes(i%251 for i in range(4000)),("10.0.0.2",9102))
PY
sleep 3
cat /tmp/f.rx

say "4) IPv6 TCP 256 KB"
ip netns exec n2 timeout 30 python3 - <<'PY' &
import socket
s=socket.socket(socket.AF_INET6); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("::",9103)); s.listen(1); s.settimeout(20)
c,_=s.accept(); buf=bytearray()
while len(buf)<256*1024:
    d=c.recv(1<<20)
    if not d: break
    buf+=d
exp=bytes(i%251 for i in range(256*1024))
print("v6 TCP received=%d correct=%d" % (len(buf),sum(1 for a,b in zip(buf,exp) if a==b)))
c.close()
PY
sleep 1
ip netns exec n1 timeout 20 python3 -c "
import socket
c=socket.socket(socket.AF_INET6); c.connect(('fd00::2',9103)); c.sendall(bytes(i%251 for i in range(256*1024))); c.shutdown(socket.SHUT_WR); c.close()"
sleep 3

say "stats + kernel log check"
cat /proc/torshield/stats
journalctl -k --since "-15 min" 2>/dev/null | grep -iE 'oops|BUG:|WARNING:|general protection|torshield' | tail -10 || echo "(no kernel complaints / journal unavailable)"
echo "DONE"
