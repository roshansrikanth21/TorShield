#!/usr/bin/env python3
"""Defragment IPv4 in a pcap and verify TorShield AEAD on each outer datagram."""
import socket
import struct
import sys

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def packets(path):
    data = open(path, "rb").read()
    magic = struct.unpack("<I", data[:4])[0]
    endian = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
    off = 24
    while off + 16 <= len(data):
        _s, _u, incl, _o = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        yield data[off:off + incl]
        off += incl


def main(path, keyhex):
    aead = ChaCha20Poly1305(bytes.fromhex(keyhex))
    groups, order = {}, []
    for p in packets(path):
        if len(p) < 34 or struct.unpack("!H", p[12:14])[0] != 0x0800:
            continue
        ip = p[14:]
        ihl = (ip[0] & 0x0F) * 4
        tot = struct.unpack("!H", ip[2:4])[0]
        ident = struct.unpack("!H", ip[4:6])[0]
        ff = struct.unpack("!H", ip[6:8])[0]
        fo = (ff & 0x1FFF) * 8
        mf = ff & 0x2000
        key = (ip[12:16], ip[16:20], ident, ip[9])
        if key not in groups:
            groups[key] = {"parts": {}, "last": 0}
            order.append(key)
        payload = ip[ihl:tot]
        groups[key]["parts"][fo] = payload
        if not mf:
            groups[key]["last"] = fo + len(payload)

    for key in order:
        g = groups[key]
        if not g["last"]:
            continue
        buf = bytearray(g["last"])
        for off, payload in g["parts"].items():
            buf[off:off + len(payload)] = payload
        if key[3] != 17 or len(buf) < 36:
            continue
        _sport, dport, _ulen = struct.unpack("!HHH", buf[:6])
        if dport != 4789:
            continue
        udp = buf[8:]
        hdr = udp[:16]
        seq = struct.unpack("!Q", hdr[8:16])[0]
        ct_len = len(udp) - 32
        ct = udp[16:16 + ct_len]
        tag = udp[16 + ct_len:32 + ct_len]
        fold = bytes(a ^ b for a, b in zip(key[0], key[1]))
        nonce = fold + struct.pack("!Q", seq)
        src = socket.inet_ntoa(key[0])
        dst = socket.inet_ntoa(key[1])
        try:
            pt = aead.decrypt(nonce, ct + tag, hdr)
            print("id=%-5d %s -> %s datagram=%d seq=%d AUTH OK inner=%d ver=%d"
                  % (key[2], src, dst, len(buf), seq, len(pt), pt[0] >> 4))
        except Exception as exc:
            print("id=%-5d %s -> %s datagram=%d seq=%d AUTH FAIL (%s)"
                  % (key[2], src, dst, len(buf), seq, type(exc).__name__))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
