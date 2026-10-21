#!/bin/bash
# Stage 7: decisive small-packet test.
#   1) one 200-byte TCP write, module loaded -> hex of wire payload on both sides
#   2) same with module unloaded (control)
#   3) 1 MB transfer with per-direction counters
set -u
cd /home/ts/ts || exit 1
KEY=$(python3 -c 'print("00112233445566778899aabbccddeeff"*2)')
say() { printf '\n=== %s ===\n' "$*"; }
modprobe chacha_x86_64

setup_mod() {
  rmmod torshield 2>/dev/null
  insmod ./torshield.ko || exit 1
  ./torshieldctl set-key "$KEY" >/dev/null
  ./torshieldctl add-peer 10.0.0.1
  ./torshieldctl add-peer 10.0.0.2
}

one_packet() {   # $1 port, $2 bytes
  local port=$1 bytes=$2
  rm -f /tmp/s.pcap /tmp/r.pcap
  ip netns exec n1 timeout 15 tcpdump -i veth1 -s 0 -w /tmp/s.pcap -U "tcp port $port" 2>/dev/null & local C1=$!
  ip netns exec n2 timeout 15 tcpdump -i veth2 -s 0 -w /tmp/r.pcap -U "tcp port $port" 2>/dev/null & local C2=$!
  sleep 2
  ip netns exec n2 timeout 10 python3 - "$port" <<'PY' &
import socket,sys
port=int(sys.argv[1])
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",port)); s.listen(1); s.settimeout(8)
c,_=s.accept(); d=c.recv(65536)
open("/tmp/app_%d.bin"%port,"wb").write(d)
print("APP got %d bytes: %s"%(len(d), d[:12]))
c.close()
PY
  sleep 1
  ip netns exec n1 timeout 6 python3 - "$port" "$bytes" <<'PY'
import socket,sys,time
port=int(sys.argv[1]); n=int(sys.argv[2])
c=socket.socket(); c.connect(("10.0.0.2",port))
c.sendall(b"Z"*n); time.sleep(0.4); c.close()
PY
  sleep 2
  kill $C1 $C2 2>/dev/null; wait $C1 $C2 2>/dev/null
  echo "--- sender-side wire ---"; python3 pcap.py dump /tmp/s.pcap "$port"
  echo "--- receiver-side wire ---"; python3 pcap.py dump /tmp/r.pcap "$port"
}

say "0) netns + TSO off"
ip netns exec n1 ethtool -K veth1 tso off gso off >/dev/null 2>&1
ip netns exec n2 ethtool -K veth2 tso off gso off >/dev/null 2>&1

say "1) MODULE LOADED: one 200-byte TCP write (port 9020)"
setup_mod
./torshieldctl list-peers
cat /proc/torshield/stats
one_packet 9020 200
echo "--- counters ---"; cat /proc/torshield/stats

say "2) MODULE UNLOADED: control (port 9021)"
rmmod torshield
one_packet 9021 200

say "3) 1 MB transfer, direction counters"
setup_mod
ip netns exec n2 timeout 20 python3 - <<'PY' &
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9022)); s.listen(1); s.settimeout(15)
c,_=s.accept(); n=0
while n<1024*1024:
    d=c.recv(1<<20)
    if not d: break
    n+=len(d)
print("receiver=%d"%n); c.close()
PY
sleep 1
ip netns exec n1 timeout 15 python3 -c "
import socket
c=socket.socket(); c.connect(('10.0.0.2',9022)); c.sendall(b'A'*(1024*1024)); c.shutdown(socket.SHUT_WR); c.close()"
sleep 2
cat /proc/torshield/stats
