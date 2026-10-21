#!/usr/bin/env python3
"""Build a TorShield tunnel packet from scratch and inject it (interop test).

usage: inject.py <iface> <dst-mac> <seq> <payload> [tamper]

The frame is built with an independent ChaCha20-Poly1305 implementation
(python-cryptography).  If the kernel accepts it, the wire format and AEAD
agree in both directions.
"""
import socket
import struct
import sys

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

KEY = bytes.fromhex("00112233445566778899aabbccddeeff"
                    "00112233445566778899aabbccddeeff")
SRC = socket.inet_aton("10.0.0.1")
DST = socket.inet_aton("10.0.0.2")
SPORT, DPORT = 9999, 9400


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_inner(payload):
    ulen = 8 + len(payload)
    udp = struct.pack("!HHHH", SPORT, DPORT, ulen, 0) + payload
    pseudo = SRC + DST + struct.pack("!BBH", 0, 17, ulen)
    c = csum(pseudo + udp)
    udp = udp[:6] + struct.pack("!H", c) + udp[8:]
    total = 20 + ulen
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0, 64, 17, 0,
                     SRC, DST)
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    return ip + udp


def main():
    iface, dstmac, seq, payload = (sys.argv[1], sys.argv[2],
                                   int(sys.argv[3]), sys.argv[4])
    tamper = len(sys.argv) > 5 and sys.argv[5] == "tamper"

    inner = build_inner(payload.encode())
    pad = (-len(inner)) % 64
    plain = inner + b"\0" * pad

    hdr = b"TS" + bytes([1, 0]) + b"\0\0\0\0" + struct.pack("!Q", seq)
    nonce = bytes(a ^ b for a, b in zip(SRC, DST)) + struct.pack("!Q", seq)
    ct_tag = ChaCha20Poly1305(KEY).encrypt(nonce, plain, hdr)

    body = bytearray(hdr + ct_tag)
    if tamper:
        body[20] ^= 0xFF

    ulen = 8 + len(body)
    udp = struct.pack("!HHHH", 4789, 4789, ulen, 0) + bytes(body)
    total = 20 + ulen
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x2222, 0, 64, 17, 0,
                     SRC, DST)
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]

    srcmac = bytes.fromhex(open("/sys/class/net/%s/address" % iface).read().strip().replace(":", ""))
    frame = bytes.fromhex(dstmac.replace(":", "")) + srcmac + \
        struct.pack("!H", 0x0800) + ip + udp

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iface, 0))
    print("sent seq=%d %d bytes%s" % (seq, s.send(frame),
                                      " (tampered)" if tamper else ""))


main()
