#!/bin/bash
# Stage 15: softdep auto-load + regression after the READ_ONCE change.
set -u
cd /home/ts/ts || exit 1
KEY=$(python3 -c 'print("00112233445566778899aabbccddeeff"*2)')
say() { printf '\n=== %s ===\n' "$*"; }

say "rebuild + install + depmod"
make 2>&1 | grep -E 'error|LD \[M\]' | tail -2
rmmod torshield 2>/dev/null
install -D -m 0644 torshield.ko /lib/modules/$(uname -r)/extra/torshield.ko
depmod -a
grep -A2 'torshield' /lib/modules/$(uname -r)/modules.softdep 2>/dev/null || echo "(no softdep entry)"

say "unload chacha, then modprobe torshield (must pull chacha itself)"
rmmod chacha_x86_64 2>&1; rmmod libchacha 2>&1
lsmod | grep -E 'chacha|torshield' || echo "chacha not loaded"
modprobe torshield; echo "modprobe rc=$?"
lsmod | grep -E 'chacha|torshield'

say "regression: small TCP marker round trip"
./torshieldctl set-key "$KEY" >/dev/null
./torshieldctl add-peer 10.0.0.1; ./torshieldctl add-peer 10.0.0.2
rm -f /tmp/g.pcap /tmp/g.rx
ip netns exec n2 timeout 12 tcpdump -i veth2 -s 0 -w /tmp/g.pcap -U "tcp port 9090" 2>/dev/null & CAP=$!
ip netns exec n2 timeout 10 python3 - <<'PY' &
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9090)); s.listen(1); s.settimeout(8)
c,_=s.accept(); d=c.recv(4096); open("/tmp/g.rx","wb").write(d); c.close()
PY
sleep 1.5
ip netns exec n1 timeout 6 python3 -c "
import socket,time
c=socket.socket(); c.connect(('10.0.0.2',9090)); c.sendall(b'SOFTDEP_OK'); time.sleep(0.3); c.close()"
sleep 2
kill $CAP 2>/dev/null; wait $CAP 2>/dev/null
echo -n "app received: "; cat /tmp/g.rx; echo
python3 pcap.py dump /tmp/g.pcap 9090 | head -3
cat /proc/torshield/stats | tr '\n' ' '; echo
