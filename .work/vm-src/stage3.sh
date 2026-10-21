#!/bin/bash
# Stage 3: fragments, encrypted-path throughput, GSO-off sanity.
set -u
cd /home/ts/ts || exit 1
KEY=$(python3 -c 'print("00112233445566778899aabbccddeeff"*2)')
say() { printf '\n=== %s ===\n' "$*"; }

modprobe chacha_x86_64
rmmod torshield 2>/dev/null; insmod ./torshield.ko
./torshieldctl set-key "$KEY" >/dev/null
./torshieldctl add-peer 10.0.0.1
./torshieldctl add-peer 10.0.0.2

say "conntrack / defrag active?"
lsmod | grep -E 'conntrack|defrag' || echo "no conntrack module loaded"

########## T4: IPv4 fragmentation ##########
say "T4 UDP 4000 B datagram, MTU 1500 (must fragment)"
ip -n n1 link set veth1 mtu 1500; ip -n n2 link set veth2 mtu 1500
rm -f /tmp/t4.pcap
ip netns exec n2 timeout 15 tcpdump -i veth2 -s 0 -w /tmp/t4.pcap -U "udp port 9003" 2>/dev/null &
CAP=$!; sleep 1.5
ip netns exec n2 timeout 10 python3 - <<'PY' >/tmp/t4.rx 2>&1 &
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
s.setsockopt(socket.IPPROTO_IP, 10, 0)     # IP_PMTUDISC_DONT -> allow fragmentation
s.sendto(b"F"*4000, ("10.0.0.2", 9003))
PY
sleep 3
kill $CAP 2>/dev/null; wait $CAP 2>/dev/null
cat /tmp/t4.rx
python3 pcap.py ipids /tmp/t4.pcap | head -10
echo "(frag field: 0x2000 = MF set, non-zero low bits = offset > 0 => non-first fragment)"

########## T5: GSO off -> is everything encrypted? ##########
say "T5 bulk TCP with TSO/GSO OFF (4 MB of 'A')"
ip netns exec n1 ethtool -K veth1 tso off gso off >/dev/null 2>&1
ip netns exec n2 ethtool -K veth2 tso off gso off >/dev/null 2>&1
ip netns exec n1 ethtool -k veth1 2>/dev/null | grep -E '^(tcp-segmentation|generic-segmentation)'
rm -f /tmp/t5.pcap
ip netns exec n2 timeout 30 tcpdump -i veth2 -s 0 -w /tmp/t5.pcap -U "tcp port 9004" 2>/dev/null &
CAP=$!; sleep 1.5
ip netns exec n2 timeout 25 python3 - <<'PY' &
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9004)); s.listen(1); s.settimeout(20)
c,_=s.accept(); n=0
while n < 4*1024*1024:
    d=c.recv(1<<20)
    if not d: break
    n+=len(d)
open("/tmp/t5.rx","w").write(str(n)); c.close()
PY
sleep 1
ip netns exec n1 timeout 20 python3 - <<'PY'
import socket
c=socket.socket(); c.connect(("10.0.0.2",9004))
buf=b"A"*(1<<20)
for _ in range(4): c.sendall(buf)
c.shutdown(socket.SHUT_WR); c.close()
PY
sleep 2
kill $CAP 2>/dev/null; wait $CAP 2>/dev/null
echo "receiver_bytes=$(cat /tmp/t5.rx 2>/dev/null)"
python3 pcap.py gso /tmp/t5.pcap 9004

########## T6: iperf3 throughput, encrypted path ##########
say "T6 iperf3 TCP, GSO already off"
perf() {
  ip netns exec n2 iperf3 -s -1 -D >/dev/null 2>&1; sleep 1
  ip netns exec n1 iperf3 -c 10.0.0.2 -t 5 -J 2>/dev/null | \
    python3 -c 'import sys,json;d=json.load(sys.stdin);print("%.1f Mbps"%(d["end"]["sum_received"]["bits_per_second"]/1e6))'
}
echo -n "WITH TorShield    : "; perf
./torshieldctl clear-peers
echo -n "WITHOUT TorShield : "; perf
