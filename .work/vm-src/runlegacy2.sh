#!/bin/bash
# Re-run the legacy tunnel/hybrid regression (stages 16-20) on the final module.
set -u
LOG=/home/ts/ts/legacy-tc.log
: > "$LOG"
for n in 16 17 18 19 20; do
    echo "##### STAGE $n #####" | tee -a "$LOG"
    # Destroy the previous stage's namespaces before rmmod: their torshield
    # devices hold the module, and a stale module would silently survive.
    ip netns del n1 2>/dev/null
    ip netns del n2 2>/dev/null
    rmmod torshield 2>/dev/null
    bash "/home/ts/ts/stage$n.sh" >> "$LOG" 2>&1
    echo "##### STAGE $n rc=$? #####" | tee -a "$LOG"
done
echo "DONE" | tee -a "$LOG"
