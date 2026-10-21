#!/bin/bash
echo "== whoami =="; id
echo "== kernel =="; uname -r
echo "== modules support =="
ls /lib/modules 2>&1 | head
(zcat /proc/config.gz 2>/dev/null || cat /boot/config-$(uname -r) 2>/dev/null) > /tmp/kconf 2>/dev/null
echo "config bytes: $(wc -c < /tmp/kconf 2>/dev/null)"
grep -E "^CONFIG_MODULES=|^CONFIG_MODULE_UNLOAD=|^CONFIG_NETFILTER=|^CONFIG_CRYPTO_CHACHA20=|^CONFIG_CRYPTO_USER" /tmp/kconf 2>/dev/null
echo "== modprobe probe =="
modprobe dummy 2>&1 | head -3
echo "== tools =="
for t in gcc make qemu-system-x86_64 python3 curl git sparse smatch pahole bc flex bison; do printf "%s: " $t; command -v $t || echo MISSING; done
echo "== sudo =="
sudo -n true 2>&1 && echo "passwordless sudo OK" || echo "sudo needs password or unavailable"
echo "== net =="
timeout 10 curl -sI https://deb.debian.org/debian/ 2>&1 | head -1
echo "== disk/mem =="
df -h / | tail -1; free -m | head -2
echo "== nproc =="; nproc
echo "== apt lists =="
ls /var/lib/apt/lists 2>/dev/null | head -3
