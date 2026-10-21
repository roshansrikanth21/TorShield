#!/bin/bash
# Stage 9: content integrity through TorShield (the test that matters).
set -u
cd /home/ts/ts || exit 1
KEY=$(python3 -c 'print("00112233445566778899aabbccddeeff"*2)')
say() { printf '\n=== %s ===\n' "$*"; }
modprobe chacha_x86_64

echo "--- veth TSO/GSO capabilities ---"
ip netns exec n1 ethtool -k veth1 2>&1 | grep -E '^(tcp-segmentation|generic-segmentation|scatter-gather|tx-checksumming)'

transfer() {   # $1 = port
  local port=$1
  ip netns exec n2 timeout 25 python3 - "$port" <<'PY' &
import socket,sys,hashlib
port=int(sys.argv[1])
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",port)); s.listen(1); s.settimeout(20)
c,_=s.accept(); buf=bytearray()
while len(buf) < 1024*1024:
    d=c.recv(1<<20)
    if not d: break
    buf += d
exp = bytes(i % 251 for i in range(1024*1024))
same = sum(1 for a,b in zip(buf,exp) if a==b)
print("%s: received=%d correct_bytes=%d (%.1f%%) first16=%s" %
      (sys.argv[0], len(buf), same, 100.0*same/len(exp), bytes(buf[:16]).hex()))
c.close()
PY
  sleep 1
  ip netns exec n1 timeout 20 python3 - "$port" <<'PY'
import socket,sys
c=socket.socket(); c.connect(("10.0.0.2",int(sys.argv[1])))
c.sendall(bytes(i % 251 for i in range(1024*1024))); c.shutdown(socket.SHUT_WR); c.close()
PY
  sleep 2
}

say "A) control: module unloaded"
rmmod torshield 2>/dev/null
ip netns exec n1 ethtool -K veth1 tso on gso on >/dev/null 2>&1
ip netns exec n2 ethtool -K veth2 tso on gso on >/dev/null 2>&1
transfer 9040

say "B) module loaded, TSO ON (default)"
insmod ./torshield.ko
./torshieldctl set-key "$KEY" >/dev/null
./torshieldctl add-peer 10.0.0.1; ./torshieldctl add-peer 10.0.0.2
transfer 9041
cat /proc/torshield/stats

say "C) module loaded, TSO OFF (attempted)"
ip netns exec n1 ethtool -K veth1 tso off gso off 2>&1
ip netns exec n2 ethtool -K veth2 tso off gso off 2>&1
ip netns exec n1 ethtool -k veth1 2>&1 | grep -E '^(tcp-segmentation|generic-segmentation)'
rmmod torshield; insmod ./torshield.ko
./torshieldctl set-key "$KEY" >/dev/null
./torshieldctl add-peer 10.0.0.1; ./torshieldctl add-peer 10.0.0.2
transfer 9042
cat /proc/torshield/stats
