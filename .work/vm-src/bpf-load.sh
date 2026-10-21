#!/bin/bash
# Load the TC classifier once to exercise the verifier and pin its maps.
set -u
cd /home/ts/ts
mkdir -p /sys/fs/bpf/torshield/maps
bpftool prog load tc/torshield_tc.o /sys/fs/bpf/torshield/prog pinmaps /sys/fs/bpf/torshield/maps
echo "load rc=$?"
bpftool prog show pinned /sys/fs/bpf/torshield/prog 2>&1 | head -4
echo "--- maps ---"
ls -l /sys/fs/bpf/torshield/maps
echo "--- allowed4 ---"
bpftool map show pinned /sys/fs/bpf/torshield/maps/allowed4 2>&1
echo "--- cleanup ---"
rm -f /sys/fs/bpf/torshield/prog
rm -rf /sys/fs/bpf/torshield
