#!/bin/bash
# Stage 2 (inside the VM, as root): datapath correctness tests.
#   T1  TCP payload round trip + wire obfuscation
#   T2  UDP keystream reuse (same-size datagrams, DF set)
#   T3  GSO plaintext leak on bulk TCP
set -u
cd /home/ts/ts || exit 1
MARKER="TORSHIELD_PLAINTEXT_MARKER_42"
KEY=$(python3 -c 'print("00112233445566778899aabbccddeeff"*2)')

say() { printf '\n=== %s ===\n' "$*"; }
start_net() {
  ip netns del n1 2>/dev/null; ip netns del n2 2>/dev/null
  ip netns add n1; ip netns add n2
  ip link add veth1 netns n1 type veth peer name veth2 netns n2
  ip -n n1 addr add 10.0.0.1/24 dev veth1
  ip -n n2 addr add 10.0.0.2/24 dev veth2
  ip -n n1 link set veth1 up; ip -n n2 link set veth2 up
  ip -n n1 link set lo up; ip -n n2 link set lo up
  sleep 1
}
load_module() {
  modprobe chacha_x86_64
  rmmod torshield 2>/dev/null
  insmod ./torshield.ko || { echo "insmod FAILED"; exit 1; }
  ./torshieldctl set-key "$KEY"
  ./torshieldctl add-peer 10.0.0.1
  ./torshieldctl add-peer 10.0.0.2
}
capture() {   # $1 = outfile, $2 = filter
  ip netns exec n2 timeout 25 tcpdump -i veth2 -s 0 -w "$1" -U "$2" 2>/dev/null &
  CAPPID=$!
  sleep 1.5
}
stop_capture() { kill "$CAPPID" 2>/dev/null; wait "$CAPPID" 2>/dev/null; }

start_net
load_module
say "module state"; ./torshieldctl status; ./torshieldctl list-peers

########## T1: TCP marker round trip ##########
say "T1 TCP marker"
rm -f /tmp/t1.pcap /tmp/t1.rx
capture /tmp/t1.pcap "tcp port 9000"
ip netns exec n2 timeout 10 python3 - <<'PY' &
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9000)); s.listen(1); s.settimeout(8)
c,_=s.accept(); data=c.recv(4096); open("/tmp/t1.rx","wb").write(data); c.close()
PY
sleep 1
ip netns exec n1 timeout 5 python3 -c "
import socket,sys,time
c=socket.socket(); c.connect(('10.0.0.2',9000)); c.sendall(b'$MARKER'); time.sleep(0.3); c.close()"
sleep 2
stop_capture
if grep -qa "$MARKER" /tmp/t1.rx; then echo "RESULT T1a receiver_got_marker=PASS"; else echo "RESULT T1a receiver_got_marker=FAIL"; fi
if tcpdump -r /tmp/t1.pcap -A 2>/dev/null | grep -qa "$MARKER"; then echo "RESULT T1b marker_on_wire=LEAK"; else echo "RESULT T1b marker_on_wire=ABSENT (good)"; fi

########## T2: UDP keystream reuse ##########
say "T2 UDP nonce reuse (two same-size datagrams, DF forced)"
rm -f /tmp/t2.pcap
capture /tmp/t2.pcap "udp port 9001"
ip netns exec n2 timeout 10 python3 - <<'PY' &
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9001)); s.settimeout(8); n=0
try:
    while n<2:
        d,_=s.recvfrom(4096); n+=1
except Exception: pass
print("udp_received=%d"%n)
PY
sleep 1
ip netns exec n1 timeout 5 python3 - <<'PY'
import socket,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IP, socket.IP_MTU_DISCOVER, socket.IP_PMTUDISC_DO)
for ch in (b"A",b"B"):
    s.sendto(ch*1000, ("10.0.0.2",9001)); time.sleep(0.2)
PY
sleep 2
stop_capture
python3 pcap.py udp /tmp/t2.pcap 9001

########## T3: GSO plaintext leak ##########
say "T3 bulk TCP with TSO/GSO on (4 MB of 'A')"
rm -f /tmp/t3.pcap
ip netns exec n2 ethtool -K veth2 tso on gso on >/dev/null 2>&1
ip netns exec n1 ethtool -K veth1 tso on gso on >/dev/null 2>&1
capture /tmp/t3.pcap "tcp port 9002"
ip netns exec n2 timeout 30 python3 - <<'PY' &
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9002)); s.listen(1); s.settimeout(20)
c,_=s.accept(); n=0
while n < 4*1024*1024:
    d=c.recv(1<<20)
    if not d: break
    n+=len(d)
open("/tmp/t3.rx","w").write(str(n)); c.close()
PY
sleep 1
ip netns exec n1 timeout 20 python3 - <<'PY'
import socket
c=socket.socket(); c.connect(("10.0.0.2",9002))
buf=b"A"*(1<<20)
for _ in range(4): c.sendall(buf)
c.shutdown(socket.SHUT_WR); c.close()
PY
sleep 2
stop_capture
echo "receiver_bytes=$(cat /tmp/t3.rx 2>/dev/null)"
python3 pcap.py gso /tmp/t3.pcap 9002
echo
echo "=== done ==="
