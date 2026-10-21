#!/bin/bash
set -u
Q=$HOME/qemu
cd "$Q/debs" || exit 1
for p in libfdt1 libpmem1 libnuma1 librdmacm1 libslirp0 liburing2 libaio1t64; do
  apt-get download "$p" >/dev/null 2>&1 || echo "dl failed: $p"
done
for d in *.deb; do dpkg-deb -x "$d" "$Q/root" 2>/dev/null; done
export LD_LIBRARY_PATH="$Q/root/usr/lib/x86_64-linux-gnu:$Q/root/lib/x86_64-linux-gnu:$Q/root/usr/lib"
echo "=== remaining missing ==="
ldd "$Q/root/usr/bin/qemu-system-x86_64" | grep 'not found' || echo "all resolved"
echo "=== version ==="
"$Q/root/usr/bin/qemu-system-x86_64" --version | head -1
"$Q/root/usr/bin/qemu-img" --version 2>/dev/null | head -1
