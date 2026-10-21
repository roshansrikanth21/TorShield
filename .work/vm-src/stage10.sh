#!/bin/bash
# Stage 10: after the GSO fix — integrity + wire check, TSO on and off.
set -u
cd /home/ts/ts || exit 1
KEY=$(python3 -c 'print("00112233445566778899aabbccddeeff"*2)')
say() { printf '\n=== %s ===\n' "$*"; }
modprobe chacha_x86_64

say "rebuild"
make 2>&1 | grep -E 'error|CC \[M\]|LD \[M\]' | tail -4

load() {
  rmmod torshield 2>/dev/null
  insmod ./torshield.ko || exit 1
  ./torshieldctl set-key "$KEY" >/dev/null
  ./torshieldctl add-peer 10.0.0.1
  ./torshieldctl add-peer 10.0.0.2
}

run() {   # $1 port, $2 label
  local port=$1 label=$2
  rm -f /tmp/i.pcap
  ip netns exec n2 timeout 30 tcpdump -i veth2 -s 0 -w /tmp/i.pcap -U "tcp port $port" 2>/dev/null &
  local CAP=$!
  ip netns exec n2 timeout 25 python3 - "$port" <<'PY' &
import socket,sys
port=int(sys.argv[1])
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",port)); s.listen(1); s.settimeout(20)
c,_=s.accept(); buf=bytearray()
while len(buf) < 512*1024:
    d=c.recv(1<<20)
    if not d: break
    buf += d
exp = bytes(i % 251 for i in range(512*1024))
same = sum(1 for a,b in zip(buf,exp) if a==b)
print("RESULT %s: received=%d correct=%d (%.1f%%) first16=%s" %
      ("$label", len(buf), same, 100.0*same/len(exp), bytes(buf[:16]).hex()))
c.close()
PY
  sleep 1.5
  ip netns exec n1 timeout 20 python3 - "$port" <<'PY'
import socket,sys
c=socket.socket(); c.connect(("10.0.0.2",int(sys.argv[1])))
c.sendall(bytes(i % 251 for i in range(512*1024))); c.shutdown(socket.SHUT_WR); c.close()
PY
  sleep 3
  kill $CAP 2>/dev/null; wait $CAP 2>/dev/null
  echo "wire:"; python3 pcap.py gso /tmp/i.pcap "$port"
  echo "head:"; python3 pcap.py dump /tmp/i.pcap "$port" | head -3
  echo "stats:"; cat /proc/torshield/stats | tr '\n' ' '; echo
}

say "A) TSO ON (default)"
ip netns exec n1 ethtool -K veth1 tso on gso on >/dev/null 2>&1
ip netns exec n2 ethtool -K veth2 tso on gso on >/dev/null 2>&1
load
run 9050 "tso-on"

say "B) TSO OFF"
ip netns exec n1 ethtool -K veth1 tso off gso off >/dev/null 2>&1
ip netns exec n2 ethtool -K veth2 tso off gso off >/dev/null 2>&1
load
run 9051 "tso-off"

say "C) control, module unloaded"
rmmod torshield
run 9052 "no-module"
