#!/bin/bash
# Native run of stages 16/17/20 with the Python helpers present.
set -u
mkdir -p /home/ts
ln -sfn /root/ts /home/ts/ts
cp -f /mnt/k/tor-project/.work/vm-src/stage*.sh /root/ts/
cp -f /mnt/k/tor-project/.work/vm-src/*.py /root/ts/
cp -f /mnt/k/tor-project/.work/verify21.sh /root/ts/ 2>/dev/null || true
export KDIR=/root/wsl-kernel
for s in 16 17 20; do
    echo "##### stage$s #####"
    bash "/root/ts/stage$s.sh" > "/mnt/k/tor-project/.work/native-stage$s.log" 2>&1
    echo "rc=$?"
    grep -E 'PASS|FAIL|correct|tun_(drop|replay|acl|roam)|echo:|outer|inner|MSS|mss' \
        "/mnt/k/tor-project/.work/native-stage$s.log" | tail -22
done
