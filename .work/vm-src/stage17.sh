#!/bin/bash
# Stage 17: replay / tamper / unknown-peer accounting + independent interop.
set -u
cd /home/ts/ts || exit 1
KEY=$(python3 -c 'print("00112233445566778899aabbccddeeff"*2)')
say() { printf '\n=== %s ===\n' "$*"; }
stat() { grep -E 'tun_' /proc/torshield/stats | tr '\n' ' '; echo; }

say "build + install"
make clean >/dev/null 2>&1
make 2>&1 | grep -E 'error|LD \[M\]' | tail -3
rmmod torshield 2>/dev/null
install -D -m 0644 torshield.ko /lib/modules/$(uname -r)/extra/torshield.ko
depmod -a
modprobe torshield; echo "modprobe rc=$?"
./torshieldctl set-key "$KEY" >/dev/null
./torshieldctl add-peer 10.0.0.1; ./torshieldctl add-peer 10.0.0.2

say "fresh netns"
ip netns del n1 2>/dev/null; ip netns del n2 2>/dev/null
ip netns add n1; ip netns add n2
ip link add veth1 netns n1 type veth peer name veth2 netns n2
ip -n n1 addr add 10.0.0.1/24 dev veth1
ip -n n1 addr add 10.0.0.99/24 dev veth1
ip -n n2 addr add 10.0.0.2/24 dev veth2
ip -n n1 link set veth1 up; ip -n n2 link set veth2 up
ip -n n1 link set lo up; ip -n n2 link set lo up
sleep 1
MAC2=$(ip netns exec n2 cat /sys/class/net/veth2/address)
echo "veth2 mac: $MAC2"

say "receiver + ingress-only capture"
rm -f /tmp/t5.pcap /tmp/rx.txt
ip netns exec n2 timeout 45 tcpdump -Q in -i veth2 -s 0 -w /tmp/t5.pcap -U "udp port 4789" 2>/dev/null & CAP=$!
ip netns exec n2 timeout 40 python3 -u - > /tmp/rx.txt 2>&1 <<'PY' &
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9400)); s.settimeout(35)
while True:
    try:
        d,_=s.recvfrom(4096)
    except Exception:
        break
    print("RX %r" % d, flush=True)
PY
sleep 2

say "1) kernel-encapsulated datagram"
ip netns exec n1 timeout 6 python3 -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.sendto(b'ONE-ORIGINAL',('10.0.0.2',9400))"
sleep 2
echo -n "after original: "; stat

say "2) replay the captured frame (same seq) -> must drop"
ip netns exec n1 python3 /home/ts/ts/replay.py /tmp/t5.pcap 4789 0 veth1 10.0.0.2
sleep 2
echo -n "after replay: "; stat

say "3) independently-built tunnel packet, new seq -> must be accepted"
ip netns exec n1 python3 /home/ts/ts/inject.py veth1 "$MAC2" 1000 FROM-PYTHON
sleep 2
echo -n "after python packet: "; stat

say "4) independently-built packet with one flipped ciphertext byte -> must drop"
ip netns exec n1 python3 /home/ts/ts/inject.py veth1 "$MAC2" 1001 TAMPERED tamper
sleep 2
echo -n "after tampered packet: "; stat

say "5) replay the accepted python packet -> must drop"
ip netns exec n1 python3 /home/ts/ts/inject.py veth1 "$MAC2" 1000 REPLAYED
sleep 2
echo -n "after python replay: "; stat

say "6) framed packet from an address that is not a peer -> must drop"
ip netns exec n1 timeout 6 python3 - <<'PY'
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(("10.0.0.99",0))
s.sendto(b'TS' + bytes([1,0]) + b'\0\0\0\0' + b'\0'*8 + b'X'*64, ("10.0.0.2",4789))
PY
sleep 1
echo -n "after unknown peer: "; stat

say "receiver output"
cat /tmp/rx.txt

kill $CAP 2>/dev/null; wait $CAP 2>/dev/null
say "capture summary"
python3 pcap.py tun /tmp/t5.pcap 4789
dmesg | grep -iE 'oops|BUG:|WARNING:|panic' | tail -5 || echo "(no kernel complaints)"
echo DONE
