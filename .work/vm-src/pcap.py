#!/usr/bin/env python3
"""Minimal pcap reader for the TorShield tests (no scapy dependency)."""
import struct
import sys


def read_pcap(path):
    data = open(path, "rb").read()
    if len(data) < 24:
        return []
    magic = struct.unpack("<I", data[:4])[0]
    if magic in (0xA1B2C3D4, 0xA1B23C4D):
        endian = "<"
    elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
        endian = ">"
    else:
        raise SystemExit("not a pcap: magic 0x%08x" % magic)
    off, out = 24, []
    while off + 16 <= len(data):
        _ts, _tu, incl, _orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        out.append(data[off:off + incl])
        off += incl
    return out


def parse(pkt):
    if len(pkt) < 14:
        return None
    ethertype = struct.unpack("!H", pkt[12:14])[0]
    ip = 14
    if ethertype == 0x86DD:
        if len(pkt) < ip + 40:
            return None
        plen = struct.unpack("!H", pkt[ip + 4:ip + 6])[0]
        nexthdr = pkt[ip + 6]
        flow = ((pkt[ip + 1] & 0x0F) << 16) | (pkt[ip + 2] << 8) | pkt[ip + 3]
        l4 = ip + 40
        end = min(len(pkt), l4 + plen)
        if nexthdr == 17 and l4 + 8 <= len(pkt):
            sport, dport, ulen = struct.unpack("!HHH", pkt[l4:l4 + 6])
            return dict(proto="udp6", ipid=flow, frag=0, sport=sport, dport=dport,
                        payload=pkt[l4 + 8:min(end, l4 + ulen)], frame=pkt)
        if nexthdr == 6 and l4 + 20 <= len(pkt):
            sport, dport = struct.unpack("!HH", pkt[l4:l4 + 4])
            doff = (pkt[l4 + 12] >> 4) * 4
            return dict(proto="tcp6", ipid=flow, frag=0, sport=sport, dport=dport,
                        flags=pkt[l4 + 13], opts=pkt[l4 + 20:l4 + doff],
                        payload=pkt[l4 + doff:end], frame=pkt)
        return dict(proto="ip6-%d" % nexthdr, ipid=flow, frag=0, sport=0, dport=0,
                    payload=b"", frame=pkt)
    if ethertype != 0x0800:
        return None
    if len(pkt) < ip + 20:
        return None
    ihl = (pkt[ip] & 0x0F) * 4
    tot = struct.unpack("!H", pkt[ip + 2:ip + 4])[0]
    ipid = struct.unpack("!H", pkt[ip + 4:ip + 6])[0]
    frag = struct.unpack("!H", pkt[ip + 6:ip + 8])[0]
    proto = pkt[ip + 9]
    l4 = ip + ihl
    end = min(len(pkt), ip + tot)
    if proto == 17 and l4 + 8 <= len(pkt):
        sport, dport, ulen = struct.unpack("!HHH", pkt[l4:l4 + 6])
        return dict(proto="udp", ipid=ipid, frag=frag, sport=sport, dport=dport,
                    payload=pkt[l4 + 8:min(end, l4 + ulen)], frame=pkt)
    if proto == 6 and l4 + 20 <= len(pkt):
        sport, dport = struct.unpack("!HH", pkt[l4:l4 + 4])
        doff = (pkt[l4 + 12] >> 4) * 4
        return dict(proto="tcp", ipid=ipid, frag=frag, sport=sport, dport=dport,
                    flags=pkt[l4 + 13], opts=pkt[l4 + 20:l4 + doff],
                    payload=pkt[l4 + doff:end], frame=pkt)
    return dict(proto=str(proto), ipid=ipid, frag=frag, sport=0, dport=0,
                payload=b"", frame=pkt)


def runs_of_a(buf, n=64):
    """Number of bytes that sit inside a run of >= n 'A' (0x41) bytes."""
    total, run = 0, 0
    for b in buf:
        if b == 0x41:
            run += 1
        else:
            if run >= n:
                total += run
            run = 0
    if run >= n:
        total += run
    return total


def tcp_mss(opts):
    """Return the MSS option value in a TCP option block, or None."""
    i = 0
    while i < len(opts):
        kind = opts[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        if i + 1 >= len(opts):
            break
        ln = opts[i + 1]
        if ln < 2 or i + ln > len(opts):
            break
        if kind == 2 and ln == 4:
            return struct.unpack("!H", opts[i + 2:i + 4])[0]
        i += ln
    return None


def main():
    cmd, path = sys.argv[1], sys.argv[2]
    pkts = [parse(p) for p in read_pcap(path)]
    pkts = [p for p in pkts if p]
    if cmd == "udp":
        dport = int(sys.argv[3]) if len(sys.argv) > 3 else None
        sel = [p for p in pkts if p["proto"] in ("udp", "udp6") and (dport is None or p["dport"] == dport)]
        print("udp_packets=%d" % len(sel))
        for p in sel:
            print("  ipid=%d frag=0x%04x len=%d head=%s" %
                  (p["ipid"], p["frag"], len(p["payload"]), p["payload"][:8].hex()))
        if len(sel) >= 2:
            c1, c2 = sel[0]["payload"], sel[1]["payload"]
            n = min(len(c1), len(c2))
            p1, p2 = b"A" * n, b"B" * n
            same = bytes(a ^ b for a, b in zip(c1[:n], c2[:n])) == \
                   bytes(a ^ b for a, b in zip(p1, p2))
            print("plaintext_pattern_a=%s" % (c1[:16] == b"A" * 16))
            print("keystream_reuse_proof=%s" % same)
    elif cmd == "gso":
        dport = int(sys.argv[3]) if len(sys.argv) > 3 else None
        sel = [p for p in pkts if p["proto"] in ("tcp", "tcp6") and (dport is None or p["dport"] == dport)]
        total = sum(len(p["payload"]) for p in sel)
        plain = sum(runs_of_a(p["payload"]) for p in sel)
        big = sum(1 for p in sel if len(p["payload"]) > 20000)
        print("tcp_segments=%d payload_bytes=%d plaintext_A_bytes=%d (%.1f%%) gso_sized_segments=%d"
              % (len(sel), total, plain, (100.0 * plain / total) if total else 0.0, big))
    elif cmd == "dump":
        dport = int(sys.argv[3]) if len(sys.argv) > 3 else None
        sel = [p for p in pkts if (dport is None or p["dport"] == dport) and p["payload"]]
        print("packets_with_payload=%d" % len(sel))
        for p in sel[:12]:
            pl = p["payload"]
            print("  %s ipid=%d len=%d head=%s |%s|" %
                  (p["proto"], p["ipid"], len(pl), pl[:24].hex(),
                   "".join(chr(b) if 32 <= b < 127 else "." for b in pl[:24])))
    elif cmd == "ipids":
        for p in pkts:
            print("%s ipid=%d frag=0x%04x len=%d" % (p["proto"], p["ipid"], p["frag"], len(p["payload"])))
    elif cmd == "mss":
        # every SYN (SYN and SYN-ACK) with an MSS option
        seen = 0
        for p in pkts:
            if p["proto"] not in ("tcp", "tcp6"):
                continue
            if not (p.get("flags", 0) & 0x02):
                continue
            m = tcp_mss(p.get("opts", b""))
            seen += 1
            print("syn sport=%d dport=%d mss=%s" % (p["sport"], p["dport"], m))
        if seen == 0:
            print("no SYN packets")
    elif cmd == "tun":
        # Inspect TorShield tunnel frames: outer UDP to 4789.
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 4789
        sel = [p for p in pkts if p["proto"] in ("udp", "udp6") and p["dport"] == port]
        print("tunnel_packets=%d" % len(sel))
        ok_hdr = 0
        bad_pad = 0
        seqs = []
        lens = []
        for p in sel:
            pl = p["payload"]
            lens.append(len(pl))
            if len(pl) >= 16 and pl[0:2] == b"TS" and pl[2] == 1:
                ok_hdr += 1
                seq = struct.unpack("!Q", pl[8:16])[0]
                seqs.append(seq)
            if len(pl) < 16 + 16 or (len(pl) - 16 - 16) % 64 != 0:
                bad_pad += 1
        print("valid_header=%d bad_padding=%d" % (ok_hdr, bad_pad))
        print("seqs=%s" % (",".join(str(s) for s in seqs[:10])))
        if lens:
            print("payload_len min=%d max=%d" % (min(lens), max(lens)))
        # plaintext leakage: look for a run of 64 'A's in the ciphertext
        plain = sum(runs_of_a(p["payload"]) for p in sel)
        print("plaintext_A_bytes=%d" % plain)
        # Inner IPv4 "45 00" or IPv6 "60" at the start of the ciphertext
        inner = sum(1 for p in sel if len(p["payload"]) > 17 and
                    (p["payload"][16] >> 4) in (4, 6))
        print("ciphertext_starts_with_ip_version=%d" % inner)
    else:
        raise SystemExit("unknown command")


main()
