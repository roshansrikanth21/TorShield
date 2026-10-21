#!/bin/bash
# Stage 16: UDP tunnel acceptance test.
# Run inside the VM as root from /home/ts/ts.
set -u
cd /home/ts/ts || exit 1
KEY=$(python3 -c 'print("00112233445566778899aabbccddeeff"*2)')
say() { printf '\n=== %s ===\n' "$*"; }

say "build + install + modprobe"
make 2>&1 | grep -E 'error|LD \[M\]' | tail -3
rmmod torshield 2>/dev/null
install -D -m 0644 torshield.ko /lib/modules/$(uname -r)/extra/torshield.ko
depmod -a
modprobe torshield; echo "modprobe rc=$?"
./torshieldctl set-key "$KEY" >/dev/null
./torshieldctl add-peer 10.0.0.1; ./torshieldctl add-peer 10.0.0.2
./torshieldctl add-peer fd00::1;  ./torshieldctl add-peer fd00::2
echo -n "mode: "; cat /proc/torshield/mode

say "netns setup"
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

say "1) small TCP marker through the tunnel (+ outer capture)"
rm -f /tmp/t1.pcap /tmp/t1.rx
ip netns exec n2 timeout 20 tcpdump -i veth2 -s 0 -w /tmp/t1.pcap -U "udp port 4789" 2>/dev/null & CAP1=$!
ip netns exec n2 timeout 15 python3 - <<'PY' &
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9300)); s.listen(1); s.settimeout(12)
c,_=s.accept(); d=c.recv(4096); open("/tmp/t1.rx","wb").write(d); c.close()
PY
sleep 1.5
ip netns exec n1 timeout 8 python3 -c "
import socket,time
c=socket.socket(); c.connect(('10.0.0.2',9300)); c.sendall(b'TUNNEL_OK'); time.sleep(0.3); c.close()"
sleep 2
kill $CAP1 2>/dev/null; wait $CAP1 2>/dev/null
echo -n "app received: "; cat /tmp/t1.rx; echo
python3 pcap.py tun /tmp/t1.pcap 4789
echo "(inner MSS is checked host-side by verify_tunnel.py: a synthetic L3"
echo " packet has no Ethernet header, so the AF_PACKET tap cannot parse it)"

say "2) TCP 1 MB integrity (v4) + outer capture"
rm -f /tmp/t2.pcap
ip netns exec n2 timeout 60 tcpdump -i veth2 -s 0 -w /tmp/t2.pcap -U "udp port 4789" 2>/dev/null & CAP=$!
ip netns exec n2 timeout 50 python3 - <<'PY' &
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9301)); s.listen(1); s.settimeout(45)
c,_=s.accept(); buf=bytearray()
while len(buf)<1024*1024:
    d=c.recv(1<<20)
    if not d: break
    buf+=d
exp=bytes(i%251 for i in range(1024*1024))
ok=sum(1 for a,b in zip(buf,exp) if a==b)
print("v4 TCP received=%d correct=%d (%.2f%%)" % (len(buf),ok,100.0*ok/len(exp)))
c.close()
PY
sleep 1.5
ip netns exec n1 timeout 45 python3 -c "
import socket
c=socket.socket(); c.connect(('10.0.0.2',9301)); c.sendall(bytes(i%251 for i in range(1024*1024))); c.shutdown(socket.SHUT_WR); c.close()"
sleep 4
kill $CAP 2>/dev/null; wait $CAP 2>/dev/null
python3 pcap.py tun /tmp/t2.pcap 4789

say "3) IPv6 TCP 256 KB integrity"
ip netns exec n2 timeout 40 python3 - <<'PY' &
import socket
s=socket.socket(socket.AF_INET6); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("::",9302)); s.listen(1); s.settimeout(35)
c,_=s.accept(); buf=bytearray()
while len(buf)<256*1024:
    d=c.recv(1<<20)
    if not d: break
    buf+=d
exp=bytes(i%251 for i in range(256*1024))
ok=sum(1 for a,b in zip(buf,exp) if a==b)
print("v6 TCP received=%d correct=%d (%.2f%%)" % (len(buf),ok,100.0*ok/len(exp)))
c.close()
PY
sleep 1
ip netns exec n1 timeout 35 python3 -c "
import socket
c=socket.socket(socket.AF_INET6); c.connect(('fd00::2',9302)); c.sendall(bytes(i%251 for i in range(256*1024))); c.shutdown(socket.SHUT_WR); c.close()"
sleep 4

say "4) UDP content + replay + tamper"
rm -f /tmp/t4.pcap /tmp/t4.rx
ip netns exec n2 timeout 30 tcpdump -Q in -i veth2 -s 0 -w /tmp/t4.pcap -U "udp port 4789" 2>/dev/null & CAP=$!
ip netns exec n2 timeout 25 python3 -u - > /tmp/t4.rx 2>&1 <<'PY' &
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9303)); s.settimeout(20)
while True:
    try:
        d,_=s.recvfrom(4096)
    except Exception:
        break
    print("RX %r" % d, flush=True)
PY
sleep 1.5
ip netns exec n1 timeout 8 python3 -c "
import socket,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.sendto(b'REPLAYTEST-ONE',('10.0.0.2',9303)); time.sleep(0.6)
s.sendto(b'TAMPER-TWO',('10.0.0.2',9303)); time.sleep(0.6)"
sleep 2
echo -n "after originals: "; grep -E 'tun_(in|rx|replay|drop)' /proc/torshield/stats | tr '\n' ' '; echo
echo "replay frame 0 (already delivered):"
ip netns exec n1 python3 /home/ts/ts/replay.py /tmp/t4.pcap 4789 0 veth1 10.0.0.2
sleep 2
echo -n "after replay: "; grep -E 'tun_(in|rx|replay|drop)' /proc/torshield/stats | tr '\n' ' '; echo
MAC2=$(ip netns exec n2 cat /sys/class/net/veth2/address)
echo "tampered fresh packet seq 5000:"
ip netns exec n1 python3 /home/ts/ts/inject.py veth1 "$MAC2" 5000 TAMPERED tamper
sleep 2
echo -n "after tamper: "; grep -E 'tun_(in|rx|replay|drop)' /proc/torshield/stats | tr '\n' ' '; echo
kill $CAP 2>/dev/null; wait $CAP 2>/dev/null
echo "receiver datagrams:"; cat /tmp/t4.rx
python3 pcap.py tun /tmp/t4.pcap 4789

say "stats"
cat /proc/torshield/stats

say "kernel log"
dmesg | grep -iE 'oops|BUG:|WARNING:|general protection|call trace|torshield' | tail -12 || true
echo DONE
