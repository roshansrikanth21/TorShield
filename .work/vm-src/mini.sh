#!/bin/bash
# Diagnose which phase produces tun_peer drops.
set -u
cd /home/ts/ts || exit 1
KEY=$(python3 -c 'print("00112233445566778899aabbccddeeff"*2)')
say() { printf '\n=== %s ===\n' "$*"; }
stat() { grep -E 'tun_' /proc/torshield/stats | tr '\n' ' '; echo; }

say "build + install"
make 2>&1 | grep -E 'error|LD \[M\]' | tail -3
rmmod torshield 2>/dev/null
install -D -m 0644 torshield.ko /lib/modules/$(uname -r)/extra/torshield.ko
depmod -a
modprobe torshield
./torshieldctl set-key "$KEY" >/dev/null
./torshieldctl add-peer 10.0.0.1; ./torshieldctl add-peer 10.0.0.2
./torshieldctl add-peer fd00::1;  ./torshieldctl add-peer fd00::2

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
echo -n "after setup: "; stat
dmesg -C

say "v4 marker (handshake only)"
ip netns exec n2 timeout 10 python3 - <<'PY' &
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9300)); s.listen(1); s.settimeout(8)
c,_=s.accept(); c.recv(16); c.close()
PY
sleep 1
ip netns exec n1 timeout 5 python3 -c "
import socket,time
c=socket.socket(); c.connect(('10.0.0.2',9300)); c.sendall(b'X'); time.sleep(0.2); c.close()"
sleep 2
echo -n "after v4 marker: "; stat
dmesg | grep -i non-peer

say "v4 bulk 1 MB"
ip netns exec n2 timeout 40 python3 - <<'PY' &
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9301)); s.listen(1); s.settimeout(35)
c,_=s.accept(); buf=bytearray()
while len(buf)<1048576:
    d=c.recv(65536)
    if not d: break
    buf+=d
print("server got", len(buf))
PY
sleep 1
ip netns exec n1 timeout 30 python3 -c "
import socket
c=socket.socket(); c.connect(('10.0.0.2',9301)); c.sendall(bytes(i%251 for i in range(1048576))); c.shutdown(socket.SHUT_WR); c.close()"
sleep 4
echo -n "after v4 bulk: "; stat
dmesg | grep -i non-peer

say "v6 bulk 256 KB"
ip netns exec n2 timeout 30 python3 - <<'PY' &
import socket
s=socket.socket(socket.AF_INET6); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("::",9302)); s.listen(1); s.settimeout(25)
c,_=s.accept(); n=0
while n<262144:
    d=c.recv(65536)
    if not d: break
    n+=len(d)
print("server6 got", n)
PY
sleep 1
ip netns exec n1 timeout 25 python3 -c "
import socket
c=socket.socket(socket.AF_INET6); c.connect(('fd00::2',9302)); c.sendall(bytes(i%251 for i in range(262144))); c.shutdown(socket.SHUT_WR); c.close()"
sleep 3
echo -n "after v6 bulk: "; stat
dmesg | grep -i non-peer
echo DONE
