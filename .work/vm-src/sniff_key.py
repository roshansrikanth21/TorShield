#!/usr/bin/env python3
"""Print the TorShield key id from the next outer IPv4/UDP:4789 frame.

usage: sniff_key.py <iface> <outer-dst> [timeout-seconds]

Used by stage23 to prove that rekey changes the *egress* key id, not only the
accepted ingress key ids.  Runs inside the namespace that owns the interface.
"""
import socket
import struct
import sys
import time

if len(sys.argv) < 3:
    sys.exit("usage: sniff_key.py <iface> <outer-dst> [timeout]")

iface = sys.argv[1]
want_dst = socket.inet_aton(sys.argv[2])
timeout = float(sys.argv[3]) if len(sys.argv) > 3 else 5.0

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
s.bind((iface, 0))
s.settimeout(timeout)
deadline = time.time() + timeout

while time.time() < deadline:
    frame = s.recv(65535)
    if len(frame) < 42 or frame[12:14] != b"\x08\x00":
        continue
    ip = frame[14:]
    ihl = (ip[0] & 0x0F) * 4
    if ip[9] != 17 or len(ip) < ihl + 8 + 16:
        continue
    if ip[16:20] != want_dst:
        continue
    udp = ip[ihl:]
    dport = struct.unpack("!H", udp[2:4])[0]
    if dport != 4789:
        continue
    ts = udp[8:]
    if ts[:2] != b"TS":
        continue
    kid = struct.unpack("!I", ts[4:8])[0]
    seq = struct.unpack("!Q", ts[8:16])[0]
    print("%d %d" % (kid, seq))
    sys.exit(0)

sys.exit(1)
