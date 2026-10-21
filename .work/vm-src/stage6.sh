#!/bin/bash
# Stage 6: is the wire capture pre- or post-decryption?
set -u
cd /home/ts/ts || exit 1
KEY=$(python3 -c 'print("00112233445566778899aabbccddeeff"*2)')
say() { printf '\n=== %s ===\n' "$*"; }
modprobe chacha_x86_64
rmmod torshield 2>/dev/null; insmod ./torshield.ko
./torshieldctl set-key "$KEY" >/dev/null

start_rx() {  # $1 port
  ip netns exec n2 timeout 25 python3 - "$1" <<'PY' &
import socket,sys
port=int(sys.argv[1])
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",port)); s.listen(1); s.settimeout(15)
c,_=s.accept(); n=0
while n<512*1024:
    d=c.recv(1<<20)
    if not d: break
    n+=len(d)
open("/tmp/rx_%d.bin"%port,"wb").write(b"")   # marker only
print("receiver_bytes=%d"%n); c.close()
PY
}
send_tx() { ip netns exec n1 timeout 15 python3 -c "
import socket
c=socket.socket(); c.connect(('10.0.0.2',$1)); c.sendall(b'A'*(512*1024)); c.shutdown(socket.SHUT_WR); c.close()"; }

say "A) both peers -> capture sender-side AND receiver-side"
./torshieldctl add-peer 10.0.0.1; ./torshieldctl add-peer 10.0.0.2
ip netns exec n1 ethtool -K veth1 tso off gso off >/dev/null 2>&1
ip netns exec n2 ethtool -K veth2 tso off gso off >/dev/null 2>&1
rm -f /tmp/tx.pcap /tmp/rx.pcap
ip netns exec n1 timeout 25 tcpdump -i veth1 -s 0 -w /tmp/tx.pcap -U "tcp port 9010" 2>/dev/null &
C1=$!
ip netns exec n2 timeout 25 tcpdump -i veth2 -s 0 -w /tmp/rx.pcap -U "tcp port 9010" 2>/dev/null &
C2=$!
sleep 2
start_rx 9010 & sleep 1
send_tx 9010
sleep 2
kill $C1 $C2 2>/dev/null; wait $C1 $C2 2>/dev/null
echo "SENDER side  :"; python3 pcap.py gso /tmp/tx.pcap 9010
echo "RECEIVER side:"; python3 pcap.py gso /tmp/rx.pcap 9010

say "B) peer .1 REMOVED -> receiver must get garbage (proves egress crypto)"
./torshieldctl del-peer 10.0.0.1
rm -f /tmp/rx2.pcap
ip netns exec n2 timeout 25 tcpdump -i veth2 -s 0 -w /tmp/rx2.pcap -U "tcp port 9011" 2>/dev/null &
C3=$!
sleep 1.5
ip netns exec n2 timeout 20 python3 -c "
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('0.0.0.0',9011)); s.listen(1); s.settimeout(10)
c,_=s.accept(); d=c.recv(4096); open('/tmp/got.bin','wb').write(d); print('first_bytes=%s'%d[:16].hex())
try: print('payload_looks_plain=%s'%(d[:16]==b'A'*16))
except Exception: pass
c.close()" &
sleep 2
send_tx 9011
sleep 3
kill $C3 2>/dev/null; wait $C3 2>/dev/null
echo "RECEIVER side (no ingress decrypt):"; python3 pcap.py gso /tmp/rx2.pcap 9011
