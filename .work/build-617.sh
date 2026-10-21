#!/bin/bash
set -u
pre=$HOME/kernels/6.17.0-42
cd "$HOME/kdeb" || exit 1
dpkg-deb -x linux-hwe-6.17-headers-6.17.0-42_6.17.0-42.42_all.deb "$pre"
kdir=$pre/usr/src/linux-headers-6.17.0-42-generic
echo "ubsan: $(readlink -f $kdir/scripts/Makefile.ubsan) exists=$([ -e $kdir/scripts/Makefile.ubsan ] && echo yes || echo no)"
for src in /mnt/k/tor-project/module/LKM /mnt/k/tor-project/original_repo/LKM /mnt/k/tor-project; do
  name=$(basename "$(dirname "$src")"); [ "$src" = /mnt/k/tor-project ] && name=kv2-selftest
  work=$HOME/bt/6.17-$name
  rm -rf "$work"; mkdir -p "$work"
  cp "$src"/*.c "$src"/Makefile "$work"/ 2>/dev/null
  echo "==== $name @ 6.17 ===="
  ( cd "$work" && make KDIR="$kdir" 2>&1 | grep -vE 'make\[[0-9]\]|Entering|Leaving|^(  )?(CC|LD|MODPOST|GEN|CALL|UPD|WRAP|HOSTCC|HOSTLD|BTF)' )
  echo "ko: $(ls "$work"/*.ko 2>/dev/null)"
done
