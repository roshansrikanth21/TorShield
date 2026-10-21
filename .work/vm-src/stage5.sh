#!/bin/bash
# Stage 5: (a) fragments with defrag loaded, (b) capture-vs-counters reconciliation.
set -u
cd /home/ts/ts || exit 1
KEY=$(python3 -c 'print("00112233445566778899aabbccddeeff"*2)')
say() { printf '\n=== %s ===\n' "$*"; }
modprobe chacha_x86_64
rmmod torshield 2>/dev/null; insmod ./torshield.ko
./torshieldctl set-key "$KEY" >/dev/null
./torshieldctl add-peer 10.0.0.1
./torshieldctl add-peer 10.0.0.2

say "a) fragments WITH nf_defrag_ipv4"
modprobe nf_defrag_ipv4; lsmod | grep defrag
ip netns exec n2 timeout 12 python3 - <<'PY' >/tmp/t4c.rx 2>&1 &
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
cat /tmp/t4c.rx
cat /proc/torshield/stats

run_tcp() {   # $1 label, $2 tso on|off, $3 port
  local label=$1 tso=$2 port=$3
  ip netns exec n1 ethtool -K veth1 tso $tso gso $tso >/dev/null 2>&1
  ip netns exec n2 ethtool -K veth2 tso $tso gso $tso >/dev/null 2>&1
  rm -f /tmp/cap.pcap
  ip netns exec n2 timeout 25 tcpdump -i veth2 -s 0 -w /tmp/cap.pcap -U "tcp port $port" 2>/dev/null &
  local CAP=$!; sleep 1.5
  ip netns exec n2 timeout 20 python3 - "$port" <<'PY' &
import socket,sys
port=int(sys.argv[1])
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",port)); s.listen(1); s.settimeout(15)
c,_=s.accept(); n=0
while n < 1024*1024:
    d=c.recv(1<<20)
    if not d: break
    n+=len(d)
print("receiver=%d"%n); c.close()
PY
  sleep 1
  ip netns exec n1 timeout 15 python3 - "$port" <<'PY'
import socket,sys
c=socket.socket(); c.connect(("10.0.0.2",int(sys.argv[1])))
c.sendall(b"A"*(1024*1024)); c.shutdown(socket.SHUT_WR); c.close()
PY
  sleep 2
  kill $CAP 2>/dev/null; wait $CAP 2>/dev/null
  echo "--- $label ---"
  python3 pcap.py gso /tmp/cap.pcap "$port"
  echo "counters:"; cat /proc/torshield/stats | tr '\n' ' '; echo
}

say "b) 1 MB TCP, TSO OFF, capture on receiver wire"
run_tcp "tso-off" off 9007
say "c) 1 MB TCP, TSO ON"
run_tcp "tso-on" on 9008
