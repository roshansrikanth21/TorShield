#!/bin/bash
set -u
Q=$HOME/qemu
cd "$Q/debs" || exit 1
apt-cache search --names-only '^seabios$' | head -2
apt-get download seabios ipxe-qemu >/dev/null 2>&1 || echo "dl issue"
for d in seabios*.deb ipxe-qemu*.deb; do [ -f "$d" ] && dpkg-deb -x "$d" "$Q/root"; done
echo "--- bios files ---"
find "$Q/root" \( -name 'bios-256k.bin' -o -name 'bios.bin' -o -name 'vgabios*.bin' \) | head
