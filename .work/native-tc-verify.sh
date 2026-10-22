#!/bin/bash
# Run native TC stage, preserve captures, then verify the wire with the host key.
set -u
mkdir -p /home/ts
ln -sfn /root/ts /home/ts/ts
cp -f /mnt/k/tor-project/.work/vm-src/stage21.sh /root/ts/
export KDIR=/root/wsl-kernel
bash /root/ts/stage21.sh 0 > /mnt/k/tor-project/.work/native-stage21b.log 2>&1
echo "stage21 rc=$?"
cp -f /tmp/t21a.pcap /tmp/t21b.pcap /tmp/t21b-n1.pcap /tmp/t21b-any.pcap /mnt/k/tor-project/.work/ 2>&1
ls -l /mnt/k/tor-project/.work/t21*.pcap 2>&1
echo "--- n1 veth1 egress ---"
tcpdump -nn -r /mnt/k/tor-project/.work/t21b-n1.pcap 2>/dev/null | grep -E 'fd01|fd00' | head -4
echo "--- n2 any ---"
tcpdump -nn -r /mnt/k/tor-project/.work/t21b-any.pcap 2>/dev/null | grep -E 'fd01|fd00' | head -4
echo "--- n2 veth2 ingress ---"
tcpdump -nn -r /mnt/k/tor-project/.work/t21b.pcap 2>/dev/null | head -4
bash /mnt/k/tor-project/.work/verify21.sh > /mnt/k/tor-project/.work/native-verify21.log 2>&1
echo "verify rc=$?"
grep -E 'tunnel_packets=|outer_pairs=|frames=' /mnt/k/tor-project/.work/native-verify21.log
echo "AUTH FAILED lines: $(grep -c 'AUTH FAILED' /mnt/k/tor-project/.work/native-verify21.log || true)"
