#!/bin/bash
echo "== modules_disabled =="; cat /proc/sys/kernel/modules_disabled 2>&1
echo "== kvm =="; ls -l /dev/kvm 2>&1
echo "== nspawn/containers =="
for t in systemd-nspawn unshare podman docker; do printf "%s: " $t; command -v $t || echo MISSING; done
echo "== unshare userns =="
unshare --user --map-root-user --mount echo "userns OK" 2>&1 | head -2
echo "== netns as user =="
unshare --user --map-root-user --net echo "netns OK (userns-mapped)" 2>&1 | head -2
echo "== tcpdump/iperf =="
for t in tcpdump iperf3 ip ethtool insmod; do printf "%s: " $t; command -v $t || echo MISSING; done
echo "== headers available? =="
ls -d /usr/src/linux-headers-* 2>&1 | head
echo "== proxy env =="
env | grep -i proxy || echo none
echo "== /dev/kvm perms if present =="
[ -e /dev/kvm ] && stat -c '%A %U %G' /dev/kvm || echo "no /dev/kvm"
