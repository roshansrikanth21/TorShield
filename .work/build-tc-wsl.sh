#!/bin/bash
set -e
mkdir -p /root/ts/tc
cp -f /mnt/k/tor-project/module/LKM/tc/Makefile \
      /mnt/k/tor-project/module/LKM/tc/torshield_tc.c \
      /mnt/k/tor-project/module/LKM/tc/torshield_tc_load.c \
      /root/ts/tc/
cd /root/ts/tc
make clean
make 2>&1
echo "=== artifacts ==="
ls -l torshield_tc.o torshield-tc
