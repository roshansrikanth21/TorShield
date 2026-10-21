#!/usr/bin/env python3
"""Send a captured Ethernet frame back onto a netns interface (replay test).

usage: replay.py <pcap> <udp-dport> <index> <iface> <dst-ip> [tamper]
"""
import socket
import struct
import sys
import time


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


def info(pkt):
    """(is_tunnel, dport, dst_str, data_offset) for IPv4/IPv6 UDP."""
    if len(pkt) < 14:
        return None
    et = struct.unpack("!H", pkt[12:14])[0]
    if et == 0x0800:
        ihl = (pkt[14] & 0x0F) * 4
        if len(pkt) < 14 + ihl + 8 or pkt[14 + 9] != 17:
            return None
        dst = socket.inet_ntop(socket.AF_INET, pkt[14 + 16:14 + 20])
        dport = struct.unpack("!H", pkt[14 + ihl + 2:14 + ihl + 4])[0]
        return dport, dst, 14 + ihl + 8
    if et == 0x86DD:
        if len(pkt) < 14 + 40 + 8 or pkt[14 + 6] != 17:
            return None
        dst = socket.inet_ntop(socket.AF_INET6, pkt[14 + 24:14 + 40])
        dport = struct.unpack("!H", pkt[14 + 40 + 2:14 + 40 + 4])[0]
        return dport, dst, 14 + 40 + 8
    return None


def main():
    path, port, index, iface, want_dst = (sys.argv[1], int(sys.argv[2]),
                                          int(sys.argv[3]), sys.argv[4],
                                          sys.argv[5])
    tamper = len(sys.argv) > 6 and sys.argv[6] == "tamper"

    frames = []
    for _ in range(40):                 # wait for tcpdump to flush
        frames = []
        for p in read_pcap(path):
            i = info(p)
            if i and i[0] == port and i[1] == want_dst:
                frames.append(p)
        if len(frames) > index:
            break
        time.sleep(0.25)
    if not frames:
        raise SystemExit("no tunnel frame for dst %s" % want_dst)
    if len(frames) <= index:
        index = len(frames) - 1
    frame = bytearray(frames[index % len(frames)])

    if tamper:
        off = info(frame)[2] + 20
        frame[off] ^= 0xFF
        print("tampered byte at offset %d" % off)

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iface, 0))
    sent = s.send(bytes(frame))
    print("sent %d bytes on %s (frame %d of %d)" % (sent, iface, index, len(frames)))


main()
