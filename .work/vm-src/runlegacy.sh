#!/bin/bash
# Re-run the legacy regression stages against the current build.
for s in 16 17 18 19; do
    echo "##### STAGE $s #####"
    dmesg -C
    bash "/home/ts/ts/stage$s.sh"
    echo "##### STAGE $s rc=$? #####"
done
