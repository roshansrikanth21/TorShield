#!/bin/bash
set -u
apt-cache show linux-headers-6.17.0-42-generic 2>/dev/null | grep -E '^(Package|Depends|Version):'
echo "--- hwe search ---"
apt-cache search --names-only 'linux-hwe-6.17-headers' 2>/dev/null | head
echo "--- direct download attempt ---"
cd "$HOME/kdeb" || exit 1
apt-get download linux-hwe-6.17-headers-6.17.0-42 2>&1 | tail -3
ls -l linux-hwe* 2>/dev/null || echo "no hwe deb"
