#!/usr/bin/env python3
"""Build a TorShield packet with an explicit outer path, key and key id.

usage: inject2.py <iface> <dst-mac> <outer-src> <outer-dst> <key-hex> <seq>
                  <inner-src> <inner-dst> <sport> <dport> <payload> [tamper]

Used for cryptokey-routing tests: per-peer keys, non-zero key ids, allowed
prefixes and endpoint roaming.  Independent of the kernel implementation
(python-cryptography ChaCha20-Poly1305).
"""
import socket
import struct
import sys

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

PORT = 4789


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def key_id(key):
    h = 2166136261
    for b in key:
        h ^= b
        h = (h * 16777619) & 0xFFFFFFFF
    return h or 1


def build_inner(src, dst, sport, dport, payload):
    ulen = 8 + len(payload)
    udp = struct.pack("!HHHH", sport, dport, ulen, 0) + payload
    pseudo = src + dst + struct.pack("!BBH", 0, 17, ulen)
    c = csum(pseudo + udp)
    udp = udp[:6] + struct.pack("!H", c) + udp[8:]
    total = 20 + ulen
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0, 64, 17, 0,
                     src, dst)
    return ip[:10] + struct.pack("!H", csum(ip)) + ip[12:] + udp


def main():
    (iface, dstmac, osrc, odst, keyhex, seq, isrc, idst, sport, dport,
     payload) = sys.argv[1:12]
    tamper = len(sys.argv) > 12 and sys.argv[12] == "tamper"

    key = bytes.fromhex(keyhex)
    kid = key_id(key)
    osrc_b, odst_b = socket.inet_aton(osrc), socket.inet_aton(odst)
    isrc_b, idst_b = socket.inet_aton(isrc), socket.inet_aton(idst)
    inner = build_inner(isrc_b, idst_b, int(sport), int(dport),
                        payload.encode())
    pad = (-len(inner)) % 64
    plain = inner + b"\0" * pad

    hdr = b"TS" + bytes([1, 0]) + struct.pack("!I", kid) + \
        struct.pack("!Q", int(seq))
    nonce = bytes(a ^ b for a, b in zip(osrc_b, odst_b)) + \
        struct.pack("!Q", int(seq))
    body = bytearray(hdr + ChaCha20Poly1305(key).encrypt(nonce, plain, hdr))
    if tamper:
        body[20] ^= 0xFF

    ulen = 8 + len(body)
    udp = struct.pack("!HHHH", PORT, PORT, ulen, 0) + bytes(body)
    total = 20 + ulen
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x2222, 0, 64, 17, 0,
                     osrc_b, odst_b)
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]

    srcmac = bytes.fromhex(
        open("/sys/class/net/%s/address" % iface).read().strip().replace(":", ""))
    frame = bytes.fromhex(dstmac.replace(":", "")) + srcmac + \
        struct.pack("!H", 0x0800) + ip + udp

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iface, 0))
    print("sent seq=%d kid=%u %s->%s inner %s->%s %d bytes%s"
          % (int(seq), kid, osrc, odst, isrc, idst, s.send(frame),
             " (tampered)" if tamper else ""))


main()
