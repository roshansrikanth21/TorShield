#!/bin/bash
set -u
Q=$HOME/qemu
cd "$Q/debs" || exit 1
for p in librdmacm1t64 libndctl6 libdaxctl1; do
  apt-get download "$p" >/dev/null 2>&1 || echo "dl failed: $p"
done
for d in *.deb; do dpkg-deb -x "$d" "$Q/root" 2>/dev/null; done
export LD_LIBRARY_PATH="$Q/root/usr/lib/x86_64-linux-gnu:$Q/root/lib/x86_64-linux-gnu:$Q/root/usr/lib"
ldd "$Q/root/usr/bin/qemu-system-x86_64" | grep 'not found' || echo "ALL RESOLVED"
"$Q/root/usr/bin/qemu-system-x86_64" --version | head -1
