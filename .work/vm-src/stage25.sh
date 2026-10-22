#!/bin/bash
# Stage 25: fail-closed guard on the FORWARD path.
#
# n1 injects an inner IPv4 packet with AF_PACKET.  That bypasses n1's
# netfilter LOCAL_OUT hook, so the packet really enters n2's FORWARD path.
# n2 forwards it towards n3; the n2 FORWARD guard must allow it only while the
# output device (veth3) has the TC egress classifier.  Removing the classifier
# must drop the packet at FORWARD, not send it in clear.
set -u
cd /home/ts/ts || exit 1
KEYG=$(python3 -c 'print("aa"*32)')
K=$(python3 -c 'print("cc"*32)')
TC=/home/ts/ts/tc/torshield-tc
OBJ=/home/ts/ts/tc/torshield_tc.o
say() { printf '\n=== %s ===\n' "$*"; }
getc() { awk -v k="$1" '$1==k {print $2}' /proc/torshield/stats; }
counters() {
    awk '$1 ~ /^(tun_out|tun_in|tun_rx|tun_drop|dev_out|dev_drop|tc_guard)$/ {printf "%s=%s ", $1, $2}' /proc/torshield/stats
    echo
}
pcap_count() {
    tcpdump -nn -q -r "$1" "$2" 2>/dev/null | wc -l
}

# AF_PACKET transmit on veth1.  No IP route, no netfilter LOCAL_OUT.
send_raw() {
    local dport="$1"
    ip netns exec n1 env MAC2="$MAC2" DSTPORT="$dport" python3 -u - <<'PY'
import os, socket, struct, time

def csum(data):
    if len(data) & 1:
        data += b'\0'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff

smac = bytes.fromhex(open('/sys/class/net/veth1/address').read().strip().replace(':', ''))
dmac = bytes.fromhex(os.environ['MAC2'].replace(':', ''))
dport = int(os.environ['DSTPORT'])
payload = b'FWD' * 64
udp = struct.pack('!HHHH', 9430, dport, 8 + len(payload), 0) + payload
src = socket.inet_aton('10.0.0.1')
dst = socket.inet_aton('10.0.0.2')
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
s.bind(('veth1', 0))
for i in range(8):
    ipid = 0x2000 + i
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), ipid,
                     0, 64, 17, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    frame = dmac + smac + struct.pack('!H', 0x0800) + ip + udp
    s.send(frame)
    time.sleep(0.05)
print('n1 injected 8 raw inner packets (AF_PACKET)')
PY
}

say "build + install"
ip netns del n1 2>/dev/null; ip netns del n2 2>/dev/null; ip netns del n3 2>/dev/null
rm -f /tmp/f25*.pcap
make 2>&1 | grep -E 'error|LD \[M\]' | tail -3
make -C tc 2>&1 | grep -E 'error|warning' | head -5
rmmod torshield 2>/dev/null
install -D -m 0644 torshield.ko /lib/modules/$(uname -r)/extra/torshield.ko
depmod -a
modprobe torshield; echo "modprobe rc=$?"
./torshieldctl set-key "$KEYG" >/dev/null

say "netns: n1 --veth1/2-- n2 --veth3/4-- n3"
ip netns add n1; ip netns add n2; ip netns add n3
ip link add veth1 netns n1 type veth peer name veth2 netns n2
ip link add veth3 netns n2 type veth peer name veth4 netns n3
ip -n n1 addr add 10.0.1.1/24 dev veth1
ip -n n2 addr add 10.0.1.2/24 dev veth2
ip -n n2 addr add 10.0.2.2/24 dev veth3
ip -n n3 addr add 10.0.2.3/24 dev veth4
ip -n n1 addr add 10.0.0.1/32 dev lo
ip -n n3 addr add 10.0.0.2/32 dev lo
ip -n n1 link set veth1 up; ip -n n2 link set veth2 up
ip -n n2 link set veth3 up; ip -n n3 link set veth4 up
ip -n n1 link set lo up; ip -n n3 link set lo up
ip -n n2 route add 10.0.0.0/24 via 10.0.2.3 dev veth3
ip netns exec n2 sysctl -qw net.ipv4.ip_forward=1
ip netns exec n2 sysctl -qw net.ipv4.conf.all.rp_filter=0
ip netns exec n2 sysctl -qw net.ipv4.conf.default.rp_filter=0
ip netns exec n2 sysctl -qw net.ipv4.conf.veth2.rp_filter=0
ip netns exec n2 sysctl -qw net.ipv4.conf.veth3.rp_filter=0
ip -n n2 sh -c 'echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' 2>/dev/null
sleep 1
echo -n "n2 route: "; ip -n n2 route get 10.0.0.2
MAC2=$(ip netns exec n2 cat /sys/class/net/veth2/address)
echo "n2 veth2 MAC: $MAC2"

say "peer + TC device on n2 egress"
./torshieldctl clear-peers
./torshieldctl add-peer 10.0.2.3 key "$K" allowed 10.0.0.2/32
./torshieldctl list-peers
ip -n n2 link add name ts2 link veth3 type torshield
ip -n n2 link set ts2 up
# Enter tc mode without a classifier: the guard must drop forwarded peer traffic.
echo tc > /proc/torshield/mode
echo -n "mode: "; cat /proc/torshield/mode

say "1) classifier absent: n2 FORWARD must drop, n3 must see nothing"
G0=$(getc tc_guard); D0=$(getc dev_out)
ip netns exec n2 timeout 8 tcpdump -Q in -i veth2 -s 0 -w /tmp/f25in.pcap -U 'ip dst 10.0.0.2' 2>/dev/null &
C1=$!
ip netns exec n3 timeout 8 tcpdump -Q in -i veth4 -s 0 -w /tmp/f25out.pcap -U 'ip dst 10.0.0.2 or udp port 4789' 2>/dev/null &
C2=$!
sleep 1
send_raw 9430
sleep 1
kill $C1 $C2 2>/dev/null; wait $C1 $C2 2>/dev/null
G1=$(getc tc_guard); D1=$(getc dev_out)
IN=$(pcap_count /tmp/f25in.pcap 'ip dst 10.0.0.2')
OUT=$(pcap_count /tmp/f25out.pcap 'ip dst 10.0.0.2 or udp port 4789')
echo "n2 ingress=$IN n3 outer=$OUT tc_guard delta=$((G1-G0)) dev_out delta=$((D1-D0))"
if [ "$IN" -ge 8 ] && [ "$OUT" = 0 ] && [ $((G1-G0)) -ge 8 ] && [ "$D1" = "$D0" ]; then
    echo "PASS: FORWARD guard dropped packets with no classifier"
else
    echo "FAIL: ingress=$IN out=$OUT guard=$((G1-G0)) dev=$((D1-D0))"
fi

say "2) classifier present: FORWARD allows TC redirect and device encap"
# No -4/-6: the loader must read the peer prefix from /proc/torshield/peers.
ip netns exec n2 "$TC" attach -o "$OBJ" -i veth3 -d ts2 || exit 1
ip netns exec n2 tc filter show dev veth3 egress | head -4
G0=$(getc tc_guard); D0=$(getc dev_out); R0=$(getc tun_rx)
ip netns exec n3 timeout 8 tcpdump -Q in -i veth4 -s 0 -w /tmp/f25out2.pcap -U 'udp port 4789' 2>/dev/null &
C2=$!
sleep 1
send_raw 9431
sleep 1
kill $C2 2>/dev/null; wait $C2 2>/dev/null
G1=$(getc tc_guard); D1=$(getc dev_out); R1=$(getc tun_rx)
OUT=$(pcap_count /tmp/f25out2.pcap 'udp port 4789')
echo "n3 pcap=$OUT tun_rx delta=$((R1-R0)) tc_guard delta=$((G1-G0)) dev_out delta=$((D1-D0))"
if [ $((R1-R0)) -ge 8 ] && [ $((G1-G0)) = 0 ] && [ $((D1-D0)) -ge 8 ]; then
    echo "PASS: FORWARD guard allowed the live TC path"
else
    echo "FAIL: pcap=$OUT rx=$((R1-R0)) guard=$((G1-G0)) dev=$((D1-D0))"
fi

say "3) delete classifier: FORWARD drops again"
ip netns exec n2 tc filter del dev veth3 egress
G0=$(getc tc_guard); D0=$(getc dev_out); R0=$(getc tun_rx)
ip netns exec n3 timeout 8 tcpdump -Q in -i veth4 -s 0 -w /tmp/f25out3.pcap -U 'udp port 4789' 2>/dev/null &
C2=$!
sleep 1
send_raw 9432
sleep 1
kill $C2 2>/dev/null; wait $C2 2>/dev/null
G1=$(getc tc_guard); D1=$(getc dev_out); R1=$(getc tun_rx)
OUT=$(pcap_count /tmp/f25out3.pcap 'udp port 4789')
echo "n3 pcap=$OUT tun_rx delta=$((R1-R0)) tc_guard delta=$((G1-G0)) dev_out delta=$((D1-D0))"
if [ "$OUT" = 0 ] && [ $((R1-R0)) = 0 ] && [ $((G1-G0)) -ge 8 ] && [ "$D1" = "$D0" ]; then
    echo "PASS: FORWARD guard dropped after classifier deletion"
else
    echo "FAIL: pcap=$OUT rx=$((R1-R0)) guard=$((G1-G0)) dev=$((D1-D0))"
fi

echo -n "final: "; counters
echo tunnel > /proc/torshield/mode
echo "DONE"
