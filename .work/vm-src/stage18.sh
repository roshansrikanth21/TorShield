#!/bin/bash
# Stage 18: hybrid TUN-style netdevice (route-based egress) + interop with
# the netfilter tunnel peer.
#
# n1: mode=hybrid, route 10.0.0.2/32 dev torshield0 (link veth1)
#     -> packets are encapsulated by ndo_start_xmit, not by POST_ROUTING
# n2: no torshield device -> replies use the normal netfilter encap
# Both sides share the same UDP:4789 AEAD wire format.
set -u
cd /home/ts/ts || exit 1
KEY=$(python3 -c 'print("00112233445566778899aabbccddeeff"*2)')
say() { printf '\n=== %s ===\n' "$*"; }
stat() { grep -E 'tun_|dev_' /proc/torshield/stats | tr '\n' ' '; echo; }

say "build + install"
make 2>&1 | grep -E 'error|LD \[M\]' | tail -3
rmmod torshield 2>/dev/null
install -D -m 0644 torshield.ko /lib/modules/$(uname -r)/extra/torshield.ko
depmod -a
modprobe torshield; echo "modprobe rc=$?"
./torshieldctl set-key "$KEY" >/dev/null
./torshieldctl add-peer 10.0.0.1; ./torshieldctl add-peer 10.0.0.2
./torshieldctl add-peer fd00::1;  ./torshieldctl add-peer fd00::2

say "netns + hybrid mode"
ip netns del n1 2>/dev/null; ip netns del n2 2>/dev/null
ip netns add n1; ip netns add n2
ip link add veth1 netns n1 type veth peer name veth2 netns n2
ip -n n1 addr add 10.0.0.1/24 dev veth1
ip -n n2 addr add 10.0.0.2/24 dev veth2
ip -n n1 addr add fd00::1/64 dev veth1 nodad 2>/dev/null
ip -n n2 addr add fd00::2/64 dev veth2 nodad 2>/dev/null
ip -n n1 link set veth1 up; ip -n n2 link set veth2 up
ip -n n1 link set lo up; ip -n n2 link set lo up
echo hybrid > /proc/torshield/mode
echo -n "mode: "; cat /proc/torshield/mode
sleep 1

say "create the TUN-style device in n1 (underlay = veth1)"
ip -n n1 link add name torshield0 link veth1 type torshield; echo "add rc=$?"
ip -n n1 link set torshield0 up
ip -n n1 route add 10.0.0.2/32 dev torshield0; echo "route rc=$?"
ip -n n1 route add fd00::2/128 dev torshield0; echo "v6 route rc=$?"
ip -n n1 route get 10.0.0.2
ip -n n1 -d link show torshield0
echo -n "route table: "; ip -n n1 route show

say "1) small TCP marker, socket bound to 10.0.0.1 (egress via torshield0)"
rm -f /tmp/t18.pcap /tmp/t18.rx
ip netns exec n2 timeout 25 tcpdump -Q in -i veth2 -s 0 -w /tmp/t18.pcap -U "udp port 4789" 2>/dev/null & CAP=$!
ip netns exec n2 timeout 20 python3 - <<'PY' &
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9300)); s.listen(1); s.settimeout(15)
c,_=s.accept(); d=c.recv(4096); open("/tmp/t18.rx","wb").write(d); c.close()
PY
sleep 1.5
ip netns exec n1 timeout 8 python3 -c "
import socket,time
c=socket.socket(); c.bind(('10.0.0.1',0))
c.connect(('10.0.0.2',9300)); c.sendall(b'HYBRID_OK'); time.sleep(0.3); c.close()"
sleep 2
echo -n "app received: "; cat /tmp/t18.rx; echo
echo -n "after small test: "; stat
kill $CAP 2>/dev/null; wait $CAP 2>/dev/null

say "2) TCP 1 MB integrity through the device path"
rm -f /tmp/t18b.pcap
ip netns exec n2 timeout 90 tcpdump -Q in -i veth2 -s 0 -w /tmp/t18b.pcap -U "udp port 4789" 2>/dev/null & CAP2=$!
ip netns exec n2 timeout 80 python3 - <<'PY' &
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9301)); s.listen(1); s.settimeout(70)
c,_=s.accept(); buf=bytearray()
while len(buf)<1048576:
    d=c.recv(65536)
    if not d: break
    buf+=d
exp=bytes(i%251 for i in range(1048576))
ok=sum(1 for a,b in zip(buf,exp) if a==b)
print("v4 TCP received=%d correct=%d (%.2f%%)" % (len(buf),ok,100.0*ok/len(exp)))
c.close()
PY
sleep 1
ip netns exec n1 timeout 70 python3 -c "
import socket
c=socket.socket(); c.bind(('10.0.0.1',0))
c.connect(('10.0.0.2',9301)); c.sendall(bytes(i%251 for i in range(1048576))); c.shutdown(socket.SHUT_WR); c.close()"
sleep 4
kill $CAP2 2>/dev/null; wait $CAP2 2>/dev/null

say "3) IPv6 TCP 256 KB integrity through the device path"
rm -f /tmp/t18c.pcap
ip netns exec n2 timeout 70 tcpdump -Q in -i veth2 -s 0 -w /tmp/t18c.pcap -U "udp port 4789" 2>/dev/null & CAP3=$!
ip netns exec n2 timeout 60 python3 - <<'PY' &
import socket
s=socket.socket(socket.AF_INET6); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("::",9302)); s.listen(1); s.settimeout(50)
c,_=s.accept(); buf=bytearray()
while len(buf)<262144:
    d=c.recv(65536)
    if not d: break
    buf+=d
exp=bytes(i%251 for i in range(262144))
ok=sum(1 for a,b in zip(buf,exp) if a==b)
print("v6 TCP received=%d correct=%d (%.2f%%)" % (len(buf),ok,100.0*ok/len(exp)))
c.close()
PY
sleep 1
ip netns exec n1 timeout 55 python3 -c "
import socket
c=socket.socket(socket.AF_INET6); c.bind(('fd00::1',0))
c.connect(('fd00::2',9302)); c.sendall(bytes(i%251 for i in range(262144))); c.shutdown(socket.SHUT_WR); c.close()"
sleep 4
kill $CAP3 2>/dev/null; wait $CAP3 2>/dev/null

say "stats"
stat
echo "device counters:"; ip -n n1 -s link show torshield0 | tail -4

say "capture summary (outer tunnel frames reaching n2)"
python3 pcap.py tun /tmp/t18.pcap 4789
python3 pcap.py tun /tmp/t18b.pcap 4789
python3 pcap.py tun /tmp/t18c.pcap 4789

say "kernel log"
dmesg | grep -iE 'oops|BUG:|WARNING:|panic|torshield' | tail -8 || echo "(none)"
echo DONE
