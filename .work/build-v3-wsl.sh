#!/bin/bash
# Real build test of the v3 module against the running WSL2 kernel headers.
set -u
SRC=/mnt/k/tor-project/module/LKM
WORK=$HOME/ts-build
rm -rf "$WORK"; mkdir -p "$WORK"
cp "$SRC"/*.c "$SRC"/Makefile "$SRC"/README.md "$WORK"/ 2>/dev/null
cd "$WORK" || exit 1
echo "== gcc =="; gcc --version | head -1
echo "== kernel =="; uname -r
echo "== headers =="; ls -d /lib/modules/$(uname -r)/build
echo
echo "== make =="
make 2>&1
echo "make exit: $?"
echo
echo "== artifacts =="
ls -l *.ko 2>/dev/null || echo "NO .ko PRODUCED"
ls -l torshieldctl 2>/dev/null || echo "NO torshieldctl"
echo
echo "== make W=1 =="
make clean >/dev/null 2>&1
make W=1 2>&1 | tail -40
