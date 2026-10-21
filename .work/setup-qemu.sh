#!/bin/bash
# Build a no-root QEMU + Debian cloud VM inside WSL2 (TCG, no KVM) so the
# TorShield module can actually be loaded, tested and benchmarked.
set -u
Q=$HOME/qemu
IMG=$HOME/vm
mkdir -p "$Q/debs" "$IMG"
cd "$Q/debs" || exit 1

echo "=== downloading qemu packages ==="
for p in qemu-system-x86 qemu-system-common qemu-system-data qemu-utils; do
  apt-get download "$p" 2>&1 | tail -1
done
for d in *.deb; do dpkg-deb -x "$d" "$Q/root"; done
echo "=== qemu binary ==="
ls -l "$Q/root/usr/bin/qemu-system-x86_64" 2>/dev/null || { echo "NO QEMU BINARY"; exit 1; }
echo "=== missing libs ==="
LD_LIBRARY_PATH="$Q/root/usr/lib/x86_64-linux-gnu:$Q/root/lib/x86_64-linux-gnu" \
  ldd "$Q/root/usr/bin/qemu-system-x86_64" | grep 'not found' || echo "all libs resolved"
echo "=== version ==="
LD_LIBRARY_PATH="$Q/root/usr/lib/x86_64-linux-gnu:$Q/root/lib/x86_64-linux-gnu" \
  "$Q/root/usr/bin/qemu-system-x86_64" --version | head -1
