#!/usr/bin/env python3
"""Independently verify TorShield tunnel packets with a reference AEAD.

Usage: verify_tunnel.py <pcap> <hex-key-32-bytes> [udp-port]

Re-implements only the framing/nonce rules and delegates the crypto to
`cryptography`'s ChaCha20Poly1305 (RFC 7539).  That makes this a real
cross-check of the in-kernel AEAD, not a round-trip.
"""
import struct
import sys

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


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


def parse(pkt, port):
    """Return (version, src_bytes, dst_bytes, l4_off, payload) or None."""
    if len(pkt) < 14:
        return None
    et = struct.unpack("!H", pkt[12:14])[0]
    if et == 0x0800:
        ip = 14
        ihl = (pkt[ip] & 0x0F) * 4
        tot = struct.unpack("!H", pkt[ip + 2:ip + 4])[0]
        if pkt[ip + 9] != 17 or ihl < 20:
            return None
        src = pkt[ip + 12:ip + 16]
        dst = pkt[ip + 16:ip + 20]
        l4 = ip + ihl
        end = ip + tot
        ver = 4
    elif et == 0x86DD:
        ip = 14
        if len(pkt) < ip + 40 or pkt[ip + 6] != 17:
            return None
        plen = struct.unpack("!H", pkt[ip + 4:ip + 6])[0]
        src = pkt[ip + 8:ip + 24]
        dst = pkt[ip + 24:ip + 40]
        l4 = ip + 40
        end = l4 + plen
        ver = 6
    else:
        return None
    if len(pkt) < l4 + 8:
        return None
    dport = struct.unpack("!H", pkt[l4 + 2:l4 + 4])[0]
    if dport != port:
        return None
    return ver, src, dst, l4, pkt[l4 + 8:end]


def fold4(ver, src, dst):
    if ver == 4:
        return bytes(a ^ b for a, b in zip(src, dst))
    # IPv6: xor the four 32-bit words of src and dst
    s = src
    d = dst
    return bytes(s[j] ^ d[j] ^ s[j + 4] ^ d[j + 4] ^
                 s[j + 8] ^ d[j + 8] ^ s[j + 12] ^ d[j + 12]
                 for j in range(4))


def tcp_mss(inner):
    if inner[0] >> 4 != 4:
        return None
    ihl = (inner[0] & 0x0F) * 4
    if inner[9] != 6 or len(inner) < ihl + 20:
        return None
    th = inner[ihl:]
    doff = (th[12] >> 4) * 4
    if not (th[13] & 0x02):
        return None
    opts = th[20:doff]
    i = 0
    while i < len(opts):
        if opts[i] == 0:
            break
        if opts[i] == 1:
            i += 1
            continue
        if i + 1 >= len(opts):
            break
        ln = opts[i + 1]
        if ln < 2 or i + ln > len(opts):
            break
        if opts[i] == 2 and ln == 4:
            return struct.unpack("!H", opts[i + 2:i + 4])[0]
        i += ln
    return None


def main():
    path, keyhex = sys.argv[1], sys.argv[2]
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 4789
    key = bytes.fromhex(keyhex)
    aead = ChaCha20Poly1305(key)

    n = ok = 0
    mss_seen = []
    for pkt in read_pcap(path):
        p = parse(pkt, port)
        if not p:
            continue
        n += 1
        ver, src, dst, l4, payload = p
        if len(payload) < 32:
            print("short payload")
            continue
        hdr = payload[:16]
        seq = struct.unpack("!Q", hdr[8:16])[0]
        ct = payload[16:-16]
        tag = payload[-16:]
        nonce = fold4(ver, src, dst) + struct.pack(">Q", seq)
        try:
            inner = aead.decrypt(nonce, ct + tag, hdr)
        except Exception as e:
            print("packet %d: AUTH FAILED (%s) seq=%d ct=%d" % (n, e, seq, len(ct)))
            continue
        ok += 1
        if n <= 5 or (len(inner) > 20 and inner[9] == 6):
            m = tcp_mss(inner)
            if m is not None:
                mss_seen.append(m)
            if n <= 5:
                print("packet %d: seq=%d ct=%d inner=%d ver=%d proto=%d %s -> %s mss=%s"
                      % (n, seq, len(ct), len(inner), inner[0] >> 4, inner[9],
                         ".".join(map(str, inner[12:16])),
                         ".".join(map(str, inner[16:20])), m))
    print("tunnel_packets=%d authenticated=%d" % (n, ok))
    if mss_seen:
        print("inner_syn_mss=%s" % sorted(set(mss_seen)))
    else:
        print("inner_syn_mss=(none captured)")


main()
