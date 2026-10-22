#!/bin/bash
set -u
install -D -m 0644 /root/ts/torshield.ko "/lib/modules/$(uname -r)/extra/torshield.ko"
depmod -a
rmmod torshield 2>/dev/null
dmesg -C
modprobe torshield
echo "modprobe rc=$?"
lsmod | grep -E 'torshield|chacha'
echo "--- mode ---"
cat /proc/torshield/mode 2>&1
echo "--- stats ---"
head -5 /proc/torshield/stats 2>&1
echo "--- dmesg ---"
dmesg | tail -20
