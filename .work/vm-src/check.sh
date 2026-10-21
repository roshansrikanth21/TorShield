cd /home/ts/ts
echo "before: $(grep -E 'tun_' /proc/torshield/stats | tr '\n' ' ')"
ip netns exec n1 python3 /home/ts/ts/replay.py /tmp/t5.pcap 4789 0 veth1 10.0.0.2
sleep 1
echo "after:  $(grep -E 'tun_' /proc/torshield/stats | tr '\n' ' ')"
ip netns exec n2 timeout 5 python3 -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('0.0.0.0',9400)); s.settimeout(2)
try:
    print('late datagram:', s.recvfrom(100)[0])
except Exception:
    print('no late datagram (replay was dropped)')
"
