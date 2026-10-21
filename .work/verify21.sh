#!/bin/bash
cd /mnt/k/tor-project/.work || exit 1
K=$(python3 -c 'print("cc"*32)')
K6=$(python3 -c 'print("dd"*32)')
KG=$(python3 -c 'print("aa"*32)')
V=vm-src/verify_tunnel.py
echo "== t21a (v4 TC requests/replies) with per-peer key K =="
python3 "$V" t21a.pcap "$K" 4789
echo "== t21a with the global PSK (must not authenticate) =="
python3 "$V" t21a.pcap "$KG" 4789
echo "== t21a outer path =="
python3 vm-src/outeraddr.py t21a.pcap 4789 | tail -3
if [ -f t21b.pcap ]; then
    echo "== t21b (v6 TC requests) with per-peer key K6 =="
    python3 "$V" t21b.pcap "$K6" 4789
    echo "== t21b with the global PSK (must not authenticate) =="
    python3 "$V" t21b.pcap "$KG" 4789
    echo "== t21b outer path =="
    python3 vm-src/outeraddr.py t21b.pcap 4789 | tail -3
fi
