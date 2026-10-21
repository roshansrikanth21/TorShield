#!/bin/bash
SSH="ssh -i $HOME/.ssh/id_ed25519 -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=20 ts@127.0.0.1"
$SSH 'set -u
echo "=== who provides chacha_crypt_arch ==="
grep -rl "chacha_crypt_arch" /lib/modules/$(uname -r)/kernel/ 2>/dev/null | head
grep "chacha" /lib/modules/$(uname -r)/modules.symbols 2>/dev/null | head
echo "=== try modprobe ==="
sudo modprobe chacha-x86_64 2>&1; echo "rc=$?"
lsmod | grep -i chacha
echo "=== retry insmod ==="
cd /home/ts/ts && sudo insmod ./torshield.ko && echo "insmod OK"
dmesg | tail -2
ls -l /proc/torshield/ 2>/dev/null' 2>&1
