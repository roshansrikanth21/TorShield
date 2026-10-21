#!/usr/bin/env python3
"""Print the outer IP src/dst and tunnel key id/seq of captured TorShield frames.

usage: outeraddr.py <pcap> [udp-port]
"""
import collections
import struct
import sys


def read_pcap(path):
    data = open(path, "rb").read()
    if len(data) < 24:
        return []
    magic = struct.unpack("<I", data[:4])[0]
    endian = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
    off, out = 24, []
    while off + 16 <= len(data):
        _ts, _tu, incl, _orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        out.append(data[off:off + incl])
        off += incl
    return out


def frames(path, port):
    for pkt in read_pcap(path):
        if len(pkt) < 14:
            continue
        et = struct.unpack("!H", pkt[12:14])[0]
        if et == 0x0800:
            ip = 14
            ihl = (pkt[ip] & 0x0F) * 4
            if pkt[ip + 9] != 17 or len(pkt) < ip + ihl + 8:
                continue
            src = ".".join(map(str, pkt[ip + 12:ip + 16]))
            dst = ".".join(map(str, pkt[ip + 16:ip + 20]))
            l4 = ip + ihl
        elif et == 0x86DD:
            ip = 14
            if pkt[ip + 6] != 17 or len(pkt) < ip + 48:
                continue
            src = ":".join("%02x%02x" % (pkt[ip + 8 + i], pkt[ip + 9 + i])
                           for i in range(0, 16, 2))
            dst = ":".join("%02x%02x" % (pkt[ip + 24 + i], pkt[ip + 25 + i])
                           for i in range(0, 16, 2))
            l4 = ip + 40
        else:
            continue
        dport = struct.unpack("!H", pkt[l4 + 2:l4 + 4])[0]
        if dport != port:
            continue
        body = pkt[l4 + 8:]
        if len(body) < 16 or body[0:2] != b"TS":
            continue
        kid = struct.unpack("!I", body[4:8])[0]
        seq = struct.unpack("!Q", body[8:16])[0]
        yield src, dst, kid, seq


def main():
    path = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 4789
    n = 0
    kids = collections.Counter()
    pairs = collections.Counter()
    for src, dst, kid, seq in frames(path, port):
        n += 1
        kids[kid] += 1
        pairs[(src, dst)] += 1
        if n <= 5:
            print("  %s -> %s kid=%u seq=%u" % (src, dst, kid, seq))
    print("frames=%d outer_pairs=%s key_ids=%s"
          % (n, dict(pairs), dict(kids)))


main()
