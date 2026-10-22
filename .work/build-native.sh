#!/bin/bash
set -e
cd /root/wsl-kernel
[ -f Module.symvers ] || cp vmlinux.symvers Module.symvers
rm -rf /root/ts
mkdir -p /root/ts
cp -a /mnt/k/tor-project/module/LKM/. /root/ts/
cd /root/ts
make KDIR=/root/wsl-kernel 2>&1 | tail -40
echo "=== vermagic ==="
modinfo -F vermagic torshield.ko 2>/dev/null || true
echo "=== undefined symbols missing CRC (modpost warnings) ==="
make KDIR=/root/wsl-kernel 2>&1 | grep -iE 'warning|undefined|no symbol' | head -20 || true
ls -l torshield.ko
