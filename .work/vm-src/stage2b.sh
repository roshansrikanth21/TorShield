#!/bin/bash
# T2 retry: UDP keystream reuse, using numeric IP_MTU_DISCOVER=10 / IP_PMTUDISC_DO=2.
set -u
cd /home/ts/ts || exit 1
KEY=$(python3 -c 'print("00112233445566778899aabbccddeeff"*2)')
modprobe chacha_x86_64
rmmod torshield 2>/dev/null; insmod ./torshield.ko
./torshieldctl set-key "$KEY" >/dev/null
./torshieldctl add-peer 10.0.0.1
./torshieldctl add-peer 10.0.0.2

run_case() {   # $1 = label, $2 = pmtudisc value
  rm -f /tmp/t2.pcap
  ip netns exec n2 timeout 12 tcpdump -i veth2 -s 0 -w /tmp/t2.pcap -U "udp port 9001" 2>/dev/null &
  CAP=$!; sleep 1.5
  ip netns exec n2 timeout 10 python3 - <<'PY' >/tmp/t2.rx 2>&1 &
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9001)); s.settimeout(8); n=0
try:
    while n<2:
        s.recvfrom(4096); n+=1
except Exception: pass
print("received=%d"%n)
PY
  sleep 1
  ip netns exec n1 timeout 6 python3 - "$2" <<'PY'
import socket, sys, time
pm = int(sys.argv[1])
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IP, 10, pm)   # IP_MTU_DISCOVER
for ch in (b"A", b"B"):
    s.sendto(ch*1000, ("10.0.0.2", 9001)); time.sleep(0.2)
PY
  sleep 2
  kill $CAP 2>/dev/null; wait $CAP 2>/dev/null
  echo "--- $1 ---"; cat /tmp/t2.rx
  python3 pcap.py udp /tmp/t2.pcap 9001
}

run_case "DF set (IP_PMTUDISC_DO=2) -> IP ID 0?" 2
run_case "DF off (IP_PMTUDISC_DONT=0) -> IP ID increments?" 0
