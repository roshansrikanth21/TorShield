#!/bin/bash
# Native rekey test (one WSL invocation).
set -u
mkdir -p /home/ts
cp -a /mnt/k/tor-project/module/LKM/. /root/ts/
cp -f /mnt/k/tor-project/.work/vm-src/stage23.sh /root/ts/
cp -f /mnt/k/tor-project/.work/vm-src/inject2.py /root/ts/
cp -f /mnt/k/tor-project/.work/vm-src/sniff_key.py /root/ts/
ln -sfn /root/ts /home/ts/ts
export KDIR=/root/wsl-kernel
bash /root/ts/stage23.sh > /mnt/k/tor-project/.work/native-stage23.log 2>&1
echo "rc=$?"
grep -E 'PASS|FAIL|delta:|received|rekey|commit|key=|prev=|tun_drop|tun_in|tun_rx' /mnt/k/tor-project/.work/native-stage23.log | tail -40
