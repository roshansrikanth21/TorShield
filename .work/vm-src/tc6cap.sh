#!/bin/bash
# Capture a few IPv6 TC-path frames for host-side AEAD verification.
# Assumes stage21 left n1/n2, veth1/veth2, ts0/ts1 and the peer table in place.
set -u
cd /home/ts/ts || exit 1
TC=/home/ts/ts/tc/torshield-tc
OBJ=/home/ts/ts/tc/torshield_tc.o
ip netns exec n1 "$TC" attach -o "$OBJ" -i veth1 -d ts0 \
    -4 10.0.0.1/32 -4 10.0.0.2/32 \
    -6 fd00::1/128 -6 fd00::2/128 || exit 1
ip netns exec n2 "$TC" attach -o "$OBJ" -i veth2 -d ts1 \
    -4 10.0.0.1/32 -4 10.0.0.2/32 \
    -6 fd00::1/128 -6 fd00::2/128 || exit 1
rm -f /tmp/t21b.pcap
ip netns exec n2 timeout 20 tcpdump -Q in -i veth2 -s 0 -w /tmp/t21b.pcap -U "udp port 4789" 2>/dev/null & CAP=$!
sleep 1.5
ip netns exec n1 timeout 10 python3 -u - <<'PY'
import socket
c = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
c.bind(("fd00::1", 0))
for i in range(8):
    c.sendto(b"V6CAP%02d" % i + b"x" * 64, ("fd00::2", 9411))
print("sent 8 v6 datagrams")
PY
sleep 1.5
kill $CAP 2>/dev/null; wait $CAP 2>/dev/null
echo -n "stats: "; grep -E 'tun_(out|in|acl|drop)|dev_(out|drop)' /proc/torshield/stats | tr '\n' ' '; echo
ip netns exec n1 "$TC" detach -i veth1
ip netns exec n2 "$TC" detach -i veth2
echo -n "mode after detach: "; cat /proc/torshield/mode
