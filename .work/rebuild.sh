#!/bin/bash
# R6: rebuild v3 against both kernel trees, capturing every warning.
set -u
for KV in 6.8.0-147 6.17.0-42; do
  kdir=$HOME/kernels/$KV/usr/src/linux-headers-$KV-generic
  work=$HOME/bt/final-$KV
  rm -rf "$work"; mkdir -p "$work"
  cp /mnt/k/tor-project/module/LKM/*.c /mnt/k/tor-project/module/LKM/Makefile "$work"/
  echo "================ $KV ================"
  ( cd "$work" && make KDIR="$kdir" 2>&1 | tee build.log | grep -E 'warning:|error:|Error|CC \[M\]' )
  rc=${PIPESTATUS[0]}
  echo "make exit=$rc"
  echo "artifacts: $(ls "$work"/*.ko 2>/dev/null | wc -l) .ko, $(ls "$work"/torshieldctl 2>/dev/null | wc -l) ctl"
  echo "warning count: $(grep -c 'warning:' "$work/build.log" || true)"
done
