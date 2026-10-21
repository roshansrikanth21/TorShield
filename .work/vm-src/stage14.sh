#!/bin/bash
# Stage 14: IPv6 datapath + malformed-packet fail-open (T1.3).
set -u
cd /home/ts/ts || exit 1
KEY=$(python3 -c 'print("00112233445566778899aabbccddeeff"*2)')
say() { printf '\n=== %s ===\n' "$*"; }
modprobe chacha_x86_64

say "setup ipv6 + load"
ip -n n1 addr add fd00::1/64 dev veth1 nodad 2>/dev/null
ip -n n2 addr add fd00::2/64 dev veth2 nodad 2>/dev/null
ip -n n1 link set veth1 up; ip -n n2 link set veth2 up
sleep 1
ip netns exec n1 ping -6 -c1 -W2 fd00::2 >/dev/null 2>&1 && echo "ipv6 ping OK" || echo "ipv6 ping FAIL"
rmmod torshield 2>/dev/null; insmod ./torshield.ko
./torshieldctl set-key "$KEY" >/dev/null
./torshieldctl add-peer 10.0.0.1; ./torshieldctl add-peer 10.0.0.2
./torshieldctl add-peer fd00::1;    ./torshieldctl add-peer fd00::2

say "A) IPv6 TCP 256 KB: integrity + wire"
rm -f /tmp/v6.pcap
ip netns exec n2 timeout 30 tcpdump -i veth2 -s 0 -w /tmp/v6.pcap -U "tcp port 9080" 2>/dev/null & CAP=$!
ip netns exec n2 timeout 25 python3 - <<'PY' &
import socket
s=socket.socket(socket.AF_INET6); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("::",9080)); s.listen(1); s.settimeout(20)
c,_=s.accept(); buf=bytearray()
while len(buf)<256*1024:
    d=c.recv(1<<20)
    if not d: break
    buf+=d
exp=bytes(i%251 for i in range(256*1024))
print("V6 TCP received=%d correct=%d" % (len(buf), sum(1 for a,b in zip(buf,exp) if a==b)))
c.close()
PY
sleep 1.5
ip netns exec n1 timeout 20 python3 -c "
import socket
c=socket.socket(socket.AF_INET6); c.connect(('fd00::2',9080)); c.sendall(bytes(i%251 for i in range(256*1024))); c.shutdown(socket.SHUT_WR); c.close()"
sleep 3
kill $CAP 2>/dev/null; wait $CAP 2>/dev/null
echo "wire:"; python3 pcap.py gso /tmp/v6.pcap 9080
python3 pcap.py dump /tmp/v6.pcap 9080 | head -3
echo "stats:"; cat /proc/torshield/stats | tr '\n' ' '; echo

say "B) IPv6 UDP two same-size datagrams (flow-label nonce)"
rm -f /tmp/v6u.pcap
ip netns exec n2 timeout 12 tcpdump -i veth2 -s 0 -w /tmp/v6u.pcap -U "udp port 9081" 2>/dev/null & CAP=$!
ip netns exec n2 timeout 10 python3 - <<'PY' &
import socket
s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("::",9081)); s.settimeout(8); got=[]
try:
    while len(got)<2: got.append(s.recvfrom(4096)[0])
except Exception: pass
print("V6 UDP received=%d content_ok=%s" % (len(got), got==[b"A"*1000,b"B"*1000]))
PY
sleep 1.5
ip netns exec n1 timeout 6 python3 - <<'PY'
import socket,time
s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)
for ch in (b"A",b"B"): s.sendto(ch*1000,("fd00::2",9081)); time.sleep(0.2)
PY
sleep 2
kill $CAP 2>/dev/null; wait $CAP 2>/dev/null
python3 pcap.py udp /tmp/v6u.pcap 9081

say "C) malformed TCP (doff=0): must pass untouched"
rm -f /tmp/bad.pcap
ip netns exec n2 timeout 12 tcpdump -i veth2 -s 0 -w /tmp/bad.pcap -U "tcp port 9082" 2>/dev/null & CAP=$!
sleep 1.5
ip netns exec n1 timeout 6 python3 - <<'PY'
import socket,struct
def csum(b):
    if len(b)%2: b+=b"\0"
    s=sum(struct.unpack("!%dH"%(len(b)//2), b))
    while s>>16: s=(s&0xffff)+(s>>16)
    return (~s)&0xffff
payload=b"M"*100
tcp=struct.pack("!HHIIBBHHH", 12345, 9082, 1, 0, 0x00, 0x02, 8192, 0, 0)  # doff=0
src=socket.inet_aton("10.0.0.1"); dst=socket.inet_aton("10.0.0.2")
tot=20+len(tcp)+len(payload)
ip=struct.pack("!BBHHHBBH4s4s",0x45,0,tot,0,0x4000,64,6,0,src,dst)
ip=ip[:10]+struct.pack("!H",csum(ip))+ip[12:]
s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
s.sendto(ip+tcp+payload,("10.0.0.2",0))
print("sent malformed")
PY
sleep 3
kill $CAP 2>/dev/null; wait $CAP 2>/dev/null
python3 pcap.py dump /tmp/bad.pcap 9082
echo "stats:"; cat /proc/torshield/stats | tr '\n' ' '; echo
