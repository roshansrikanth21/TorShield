#!/bin/bash
# Run the TorShield tests natively on the WSL2 kernel (root).
# Expects /root/wsl-kernel to have Module.symvers and /root/ts to be the source.
set -u
mkdir -p /home/ts
ln -sfn /root/ts /home/ts/ts
cp -f /mnt/k/tor-project/.work/vm-src/stage21.sh \
      /mnt/k/tor-project/.work/vm-src/stage22.sh /root/ts/
export KDIR=/root/wsl-kernel
echo "##### stage22 (rate limiter) #####"
bash /root/ts/stage22.sh > /mnt/k/tor-project/.work/native-stage22.log 2>&1
echo "rc=$?"
echo "##### stage21 (TC) #####"
bash /root/ts/stage21.sh 0 > /mnt/k/tor-project/.work/native-stage21.log 2>&1
echo "rc=$?"
echo "##### summaries #####"
grep -E 'PASS|FAIL|delta:|round trips|echo:|server:|tun_out=|dev_out|mode after|attached|detached' \
  /mnt/k/tor-project/.work/native-stage22.log \
  /mnt/k/tor-project/.work/native-stage21.log | head -60
