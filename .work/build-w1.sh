#!/bin/bash
set -u
for KV in 6.8.0-147 6.17.0-42; do
  kdir=$HOME/kernels/$KV/usr/src/linux-headers-$KV-generic
  work=$HOME/bt/w1-$KV
  rm -rf "$work"; mkdir -p "$work"
  cp /mnt/k/tor-project/module/LKM/*.c /mnt/k/tor-project/module/LKM/Makefile "$work"/
  echo "=============== W=1 $KV ==============="
  ( cd "$work" && make KDIR="$kdir" W=1 2>&1 | grep -E 'torshield|warning:|error:' | grep -v 'compiler differs' | head -40 )
  echo "ko: $(ls $work/*.ko 2>/dev/null)"
done
