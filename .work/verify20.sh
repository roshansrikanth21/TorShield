#!/bin/bash
cd /mnt/k/tor-project/.work || exit 1
K=$(python3 -c 'print("cc"*32)')
K2=$(python3 -c 'print("ee"*32)')
KG=$(python3 -c 'print("aa"*32)')
V=vm-src/verify_tunnel.py
echo "== t20a (v4 echo requests) with per-peer key K =="
python3 "$V" t20a.pcap "$K" 4789
echo "== t20a with the global PSK (must not authenticate) =="
python3 "$V" t20a.pcap "$KG" 4789
echo "== t20b (K2 test) with per-peer key K2 =="
python3 "$V" t20b.pcap "$K2" 4789
echo "== t20b with K (different peer key, must not authenticate) =="
python3 "$V" t20b.pcap "$K" 4789
echo "== t20a outer path =="
python3 vm-src/outeraddr.py t20a.pcap 4789 | tail -2
echo "== t20b outer path =="
python3 vm-src/outeraddr.py t20b.pcap 4789
