#!/bin/bash
# Stage 19: large inner UDP datagrams through tunnel mode.
# The egress hook runs before IP fragmentation, so the whole datagram is
# sealed into ONE outer packet, which the outer IP layer must then fragment
# and the receiver must reassemble before LOCAL_IN decapsulation.
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
modprobe torshield; echo "modprobe rc=$?"
./torshieldctl set-key "$KEY" >/dev/null
./torshieldctl add-peer 10.0.0.1; ./torshieldctl add-peer 10.0.0.2

ip netns del n1 2>/dev/null; ip netns del n2 2>/dev/null
ip netns add n1; ip netns add n2
ip link add veth1 netns n1 type veth peer name veth2 netns n2
ip -n n1 addr add 10.0.0.1/24 dev veth1
ip -n n2 addr add 10.0.0.2/24 dev veth2
ip -n n1 link set veth1 up; ip -n n2 link set veth2 up
ip -n n1 link set lo up; ip -n n2 link set lo up
sleep 1

say "receiver (collects both datagrams) + outer capture (all IP fragments)"
rm -f /tmp/t19.pcap /tmp/t19.txt
ip netns exec n2 timeout 40 tcpdump -Q in -i veth2 -s 0 -w /tmp/t19.pcap -U "ip proto 17" 2>/dev/null & CAP=$!
ip netns exec n2 timeout 35 python3 -u - > /tmp/t19.txt 2>&1 <<'PY' &
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9500)); s.settimeout(30)
while True:
    try:
        d,_=s.recvfrom(70000)
    except Exception:
        break
    exp=bytes(i%251 for i in range(len(d)))
    ok=sum(1 for a,b in zip(d,exp) if a==b)
    print("RX len=%d correct=%d (%.2f%%)" % (len(d),ok,100.0*ok/len(d)), flush=True)
PY
sleep 2

say "1) 4000-byte UDP datagram"
ip netns exec n1 timeout 8 python3 -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.sendto(bytes(i%251 for i in range(4000)),('10.0.0.2',9500))"
sleep 2
echo -n "stats after 4000: "; stat

say "2) 60000-byte UDP datagram"
ip netns exec n1 timeout 10 python3 -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.sendto(bytes(i%251 for i in range(60000)),('10.0.0.2',9500))"
sleep 3
echo -n "stats after 60000: "; stat

kill $CAP 2>/dev/null; wait $CAP 2>/dev/null
say "receiver output"
cat /tmp/t19.txt

say "outer datagram fragmentation (grouped by IPv4 id)"
python3 - /tmp/t19.pcap <<'PY'
import socket, struct, sys, collections

data = open(sys.argv[1], "rb").read()
endian = "<" if struct.unpack("<I", data[:4])[0] in (0xA1B2C3D4, 0xA1B23C4D) else ">"
off, pkts = 24, []
while off + 16 <= len(data):
    _s, _u, incl, _o = struct.unpack(endian + "IIII", data[off:off + 16])
    off += 16
    pkts.append(data[off:off + incl]); off += incl

groups = collections.defaultdict(list)
for p in pkts:
    if len(p) < 34 or struct.unpack("!H", p[12:14])[0] != 0x0800:
        continue
    ip = p[14:]
    ihl = (ip[0] & 0x0f) * 4
    tot = struct.unpack("!H", ip[2:4])[0]
    ident = struct.unpack("!H", ip[4:6])[0]
    frag = struct.unpack("!H", ip[6:8])[0]
    fo = (frag & 0x1fff) * 8
    mf = bool(frag & 0x2000)
    groups[ident].append((fo, tot - ihl, mf))

for ident, frags in sorted(groups.items()):
    frags.sort()
    total = sum(l for _o, l, _m in frags)
    print("id=%-5d fragments=%-3d bytes=%-6d offsets=%s" %
          (ident, len(frags), total, [o for o, _l, _m in frags][:6]))
PY

say "kernel log"
dmesg | grep -iE 'oops|BUG:|WARNING:|panic|torshield' | tail -6 || echo "(none)"
echo DONE
