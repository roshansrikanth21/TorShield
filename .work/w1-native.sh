#!/bin/bash
set -u
cd /root/ts || exit 1
KDIR=/root/wsl-kernel make clean >/dev/null 2>&1
KDIR=/root/wsl-kernel make W=1 > /mnt/k/tor-project/.work/native-w1.log 2>&1
rc=$?
grep -E 'warning:|error:|LD \[M\]' /mnt/k/tor-project/.work/native-w1.log | head -40
echo "rc=$rc"
