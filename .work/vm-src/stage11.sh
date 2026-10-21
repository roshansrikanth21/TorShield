#!/bin/bash
# Stage 11: verify the UDP nonce fix (no keystream reuse) + payload integrity.
set -u
cd /home/ts/ts || exit 1
KEY=$(python3 -c 'print("00112233445566778899aabbccddeeff"*2)')
say() { printf '\n=== %s ===\n' "$*"; }
modprobe chacha_x86_64

say "rebuild + load"
make 2>&1 | grep -E 'error|CC \[M\]|LD \[M\]' | tail -3
rmmod torshield 2>/dev/null; insmod ./torshield.ko
./torshieldctl set-key "$KEY" >/dev/null
./torshieldctl add-peer 10.0.0.1; ./torshieldctl add-peer 10.0.0.2

run_case() {   # $1 pmtudisc, $2 port, $3 tag
  local pm=$1 port=$2 tag=$3
  rm -f /tmp/u.pcap
  ip netns exec n2 timeout 12 tcpdump -i veth2 -s 0 -w /tmp/u.pcap -U "udp port $port" 2>/dev/null &
  local CAP=$!; sleep 1.5
  ip netns exec n2 timeout 10 python3 - "$port" <<'PY' >/tmp/u.rx 2>&1 &
import socket,sys
port=int(sys.argv[1])
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",port)); s.settimeout(8)
got=[]
try:
    while len(got)<2:
        d,_=s.recvfrom(8192); got.append(d)
except Exception: pass
exp=[b"A"*1000, b"B"*1000]
print("received=%d content_ok=%s" % (len(got), got==exp))
PY
  sleep 1
  ip netns exec n1 timeout 6 python3 - "$pm" "$port" <<'PY'
import socket,sys,time
pm=int(sys.argv[1]); port=int(sys.argv[2])
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IP,10,pm)
for ch in (b"A",b"B"):
    s.sendto(ch*1000,("10.0.0.2",port)); time.sleep(0.2)
PY
  sleep 2
  kill $CAP 2>/dev/null; wait $CAP 2>/dev/null
  echo "--- $tag ---"; cat /tmp/u.rx
  python3 pcap.py udp /tmp/u.pcap "$port"
}

say "DF set (the case that used to reuse the keystream)"
run_case 2 9060 "DF=DO"
say "DF off"
run_case 0 9061 "DF=DONT"
echo
echo "final stats:"; cat /proc/torshield/stats | tr '\n' ' '; echo
