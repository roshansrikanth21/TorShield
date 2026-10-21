#!/usr/bin/env python3
"""List distinct (src,dst,proto,dport) of tunnel frames in a pcap."""
import socket
import struct
import sys


def read_pcap(path):
    data = open(path, "rb").read()
    magic = struct.unpack("<I", data[:4])[0]
    endian = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
    off, out = 24, []
    while off + 16 <= len(data):
        _ts, _tu, incl, _orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        out.append(data[off:off + incl])
        off += incl
    return out


for path in sys.argv[1:]:
    seen = {}
    for pkt in read_pcap(path):
        if len(pkt) < 14:
            continue
        et = struct.unpack("!H", pkt[12:14])[0]
        if et == 0x0800:
            ihl = (pkt[14] & 0x0F) * 4
            if pkt[14 + 9] != 17:
                continue
            src = socket.inet_ntop(socket.AF_INET, pkt[14 + 12:14 + 16])
            dst = socket.inet_ntop(socket.AF_INET, pkt[14 + 16:14 + 20])
            dport = struct.unpack("!H", pkt[14 + ihl + 2:14 + ihl + 4])[0]
            key = ("v4", src, dst, dport)
        elif et == 0x86DD:
            if pkt[14 + 6] != 17:
                continue
            src = socket.inet_ntop(socket.AF_INET6, pkt[14 + 8:14 + 24])
            dst = socket.inet_ntop(socket.AF_INET6, pkt[14 + 24:14 + 40])
            dport = struct.unpack("!H", pkt[14 + 40 + 2:14 + 40 + 4])[0]
            key = ("v6", src, dst, dport)
        else:
            continue
        seen[key] = seen.get(key, 0) + 1
    print(path)
    for k, n in sorted(seen.items()):
        print("  %-3s %-40s -> %-40s dport=%-5d n=%d" % (k[0], k[1], k[2], k[3], n))
