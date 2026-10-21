#!/bin/bash
# Stage 8: rebuild in-VM, then reconcile counters with the wire for 1 MB TCP.
set -u
cd /home/ts/ts || exit 1
KEY=$(python3 -c 'print("00112233445566778899aabbccddeeff"*2)')
say() { printf '\n=== %s ===\n' "$*"; }

say "rebuild"
make 2>&1 | grep -E 'error|warning: [^t]|CC \[M\]|LD \[M\]' | tail -8
ls -l torshield.ko

modprobe chacha_x86_64
rmmod torshield 2>/dev/null; insmod ./torshield.ko || exit 1
./torshieldctl set-key "$KEY" >/dev/null
./torshieldctl add-peer 10.0.0.1
./torshieldctl add-peer 10.0.0.2
ip netns exec n1 ethtool -K veth1 tso off gso off >/dev/null 2>&1
ip netns exec n2 ethtool -K veth2 tso off gso off >/dev/null 2>&1
echo "--- counters at start ---"; cat /proc/torshield/stats

say "1 MB TCP, capture on receiver wire"
rm -f /tmp/m.pcap
ip netns exec n2 timeout 30 tcpdump -i veth2 -s 0 -w /tmp/m.pcap -U "tcp port 9030" 2>/dev/null &
CAP=$!
sleep 2
ip netns exec n2 timeout 25 python3 - <<'PY' &
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9030)); s.listen(1); s.settimeout(20)
c,_=s.accept(); n=0
while n<1024*1024:
    d=c.recv(1<<20)
    if not d: break
    n+=len(d)
print("receiver=%d"%n); c.close()
PY
sleep 1
ip netns exec n1 timeout 20 python3 -c "
import socket
c=socket.socket(); c.connect(('10.0.0.2',9030)); c.sendall(b'A'*(1024*1024)); c.shutdown(socket.SHUT_WR); c.close()"
sleep 3
kill $CAP 2>/dev/null; wait $CAP 2>/dev/null
echo "--- counters after ---"; cat /proc/torshield/stats
echo "--- wire ---"; python3 pcap.py gso /tmp/m.pcap 9030
echo "--- first 6 payload heads (ciphertext iff random) ---"; python3 pcap.py dump /tmp/m.pcap 9030
