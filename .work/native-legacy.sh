#!/bin/bash
# Native run of legacy stages 16-20 on kernel 6.18.54.1 (all in one WSL VM).
set -u
mkdir -p /home/ts
ln -sfn /root/ts /home/ts/ts
cp -f /mnt/k/tor-project/.work/vm-src/stage*.sh /root/ts/
export KDIR=/root/wsl-kernel
for s in 16 17 18 19 20; do
    echo "##### stage$s #####"
    bash "/root/ts/stage$s.sh" > "/mnt/k/tor-project/.work/native-stage$s.log" 2>&1
    echo "rc=$?"
    grep -E 'PASS|FAIL|ERROR|echo:|round trips|100%|bytes|dev_out|tun_out|tun_drop|tun_replay|tun_acl|gso|mtu' \
        "/mnt/k/tor-project/.work/native-stage$s.log" | tail -18
done
