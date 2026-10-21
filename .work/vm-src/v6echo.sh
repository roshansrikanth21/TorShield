#!/bin/bash
# IPv6 echo loop with per-iteration diagnostics and both-direction capture.
set -u
cd /home/ts/ts || exit 1
K6=$(python3 -c 'print("dd"*32)')
stat() { grep -E 'tun_(out|in|rx|drop|replay|peer|acl|roam)' /proc/torshield/stats | tr '\n' ' '; echo; }

./torshieldctl clear-peers
./torshieldctl add-peer fd00::2 key "$K6" allowed fd00::1/128,fd00::2/128
echo -n "before: "; stat

rm -f /tmp/v6req.pcap /tmp/v6rep.pcap /tmp/v6srv2.txt
ip netns exec n2 timeout 20 tcpdump -Q in -i veth2 -s 0 -w /tmp/v6req.pcap -U "udp port 4789" 2>/dev/null & C1=$!
ip netns exec n1 timeout 20 tcpdump -Q in -i veth1 -s 0 -w /tmp/v6rep.pcap -U "udp port 4789" 2>/dev/null & C2=$!
ip netns exec n2 timeout 18 python3 -u - > /tmp/v6srv2.txt 2>&1 <<'PY' &
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind(("::", 9411)); s.settimeout(15)
for i in range(8):
    d, a = s.recvfrom(4096)
    print("srv got %d from %s" % (i, a[0]), flush=True)
    s.sendto(d, a)
print("srv done", flush=True)
PY
SRV=$!
sleep 1.5
ip netns exec n1 timeout 15 python3 -u - <<'PY'
import socket
c = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); c.settimeout(3)
for i in range(8):
    msg = b"PING%d" % i
    try:
        c.sendto(msg, ("fd00::2", 9411))
        d, a = c.recvfrom(4096)
        print("cli %d reply=%r" % (i, d), flush=True)
    except Exception as e:
        print("cli %d FAILED %s" % (i, e), flush=True)
        break
PY
wait $SRV 2>/dev/null
kill $C1 $C2 2>/dev/null; wait $C1 $C2 2>/dev/null
echo "server log:"; cat /tmp/v6srv2.txt
echo -n "after: "; stat
echo "requests (n2 ingress):"; ip netns exec n2 python3 outeraddr.py /tmp/v6req.pcap 4789
echo "replies (n1 ingress):"; ip netns exec n1 python3 outeraddr.py /tmp/v6rep.pcap 4789
echo "dmesg:"; dmesg | tail -4
