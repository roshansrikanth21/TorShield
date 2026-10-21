#!/bin/bash
W=/home/roshan/ts_selftest
rm -rf "$W"; mkdir -p "$W"
cp /mnt/d/TorShield_Module/test/ts_selftest.c "$W"/
cd "$W"
gcc -Wall -Wextra -O2 -fno-strict-aliasing -o ts_selftest ts_selftest.c && echo "compile: OK" || { echo "compile: FAIL"; exit 1; }
echo "----"
./ts_selftest
