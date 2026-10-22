# TorShield kernel module (v4)

Authenticated, encrypted point-to-point tunnel for Linux, implemented as a
kernel module. Canonical source: `torshield.c` in this directory.

This is a corrected rewrite of the original `xor_obfuscation` module. It is a
research/teaching artifact, **not** a replacement for WireGuard, IPsec or TLS.

## Modes

`/proc/torshield/mode` selects the datapath (global, applies to every netns):

| Value | Mode | Behaviour |
|---|---|---|
| `tunnel` | **default** | Netfilter `POST_ROUTING` encapsulates traffic to configured peers in UDP:4789; `LOCAL_IN` (after IP reassembly) authenticates and re-injects |
| `hybrid` | opt-in | `torshield0` netdevice (`rtnl_link_ops` kind `torshield`) encapsulates traffic routed into it; netfilter still handles all other peer traffic |
| `tc` | opt-in | Netfilter egress is bypassed; a clsact/eBPF classifier on the underlay redirects matching inner packets to the same `torshield` device |
| `stream` | legacy | Length-preserving payload transform, retained for comparison; **no integrity/authentication** |

Tunnel, hybrid and TC share one wire format and interoperate.

## Peers and cryptokey routing

Each peer has its own key, allowed inner prefixes and outer endpoint:

```bash
# endpoint                         key     inner prefixes
sudo ./torshieldctl add-peer 10.0.1.2 key <64-hex> allowed 10.0.0.1/32,10.0.0.2/32
sudo ./torshieldctl add-peer fd01::2  key <64-hex> allowed fd00::1/128,fd00::2/128
```

- A **deterministic 32-bit key id** (FNV-1a of the key) travels in the header
  (bytes 4..7); `0` is reserved for the legacy global PSK.
- Egress picks the peer by **longest-prefix match** on the inner destination;
  ingress checks the inner **source** against that peer's allowed prefixes.
- The endpoint **roams** to the last authenticated sender.

This lets the inner prefixes differ from the underlay, so the route-based hybrid
device and the TC classifier can carry prefixes that overlap the underlay.

## Crypto and framing

- **ChaCha20-Poly1305** (RFC 7539), synchronous, using the in-kernel ChaCha20
  helper plus a Poly1305 implementation, because `gcm(aes)` is async and cannot
  be used from softirq context.
- Wire format: `outer IP | UDP:4789 | 16-byte header | padded ciphertext | 16-byte tag`.
  The header is the AAD; the nonce is a 4-byte XOR fold of the outer addresses
  followed by the 64-bit big-endian sequence number.
- Plaintext is zero-padded to 64-byte buckets; the inner header determines the
  real length after decryption.
- Replay window: 1024 packets per peer, advanced only after successful
  authentication (4-stream reordering exceeded the old 64-packet window).
- Outer IPv4 packets get a per-packet IP ID so fragmented datagrams are safe.

## Build

Requires kernel headers for the running kernel and a C toolchain:

```bash
sudo apt-get install -y build-essential linux-headers-$(uname -r)
make                       # builds torshield.ko and torshieldctl
```

Verified clean (`make W=1`) on 6.8.0-147 and 6.17.0-42.

The TC path builds separately (`clang`, `libbpf-dev` required):

```bash
cd tc
make                       # builds torshield_tc.o and torshield-tc
```

## Usage

On **both** hosts, with the same pre-shared key:

```bash
sudo modprobe torshield
sudo ./torshieldctl set-key 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
sudo ./torshieldctl add-peer 10.0.0.2
sudo ./torshieldctl list-peers
sudo ./torshieldctl status                    # set / unset
```

The module stays inert until a PSK **and** at least one peer are configured, so
loading it never disrupts the box. Remove and unload:

```bash
sudo ./torshieldctl clear-peers
sudo rmmod torshield
```

### Hybrid device

```bash
echo hybrid | sudo tee /proc/torshield/mode
sudo ip link add name torshield0 link eth0 type torshield
sudo ip link set torshield0 up
sudo ip route add 10.0.0.2/32 dev torshield0
```

`link DEV` selects the underlay interface; the outer route lookup is pinned to
it so the route to the inner peer cannot recurse back into the device. The
device MTU is 1360 (`min 576`, `max 1360`), giving a TCP MSS of 1320.

Because peers carry their own allowed inner prefixes and endpoint (see above),
the route into `torshield0` can target inner prefixes that differ from the
underlay. Packets routed into the device are skipped by the netfilter egress
hook and encapsulated by `ndo_start_xmit`; everything else still uses the
transparent path, so a hybrid peer interoperates with a plain tunnel peer.

### TC device (clsact/eBPF)

```bash
# run in the namespace that owns the underlay
sudo torshield-tc attach -o tc/torshield_tc.o -i eth0 -d torshield0 \
    -4 10.0.0.1/32 -4 10.0.0.2/32 \
    -6 fd00::1/128 -6 fd00::2/128
sudo torshield-tc detach -i eth0
```

`attach` loads the object, fills the LPM maps, attaches to the underlay's clsact
egress, and only then writes `tc` to the mode file; `detach` writes `tunnel`
first and then removes the qdisc. The classifier redirects matching packets to
the per-namespace `torshield` device (outer frames carry `TS_TC_MARK` so they
are not redirected twice) and `ndo_start_xmit` strips the L2 header TC supplies.
Each namespace needs its own attach, because the redirect ifindex is stored per
classifier instance.

> **Fail-open.** Netfilter `POST_ROUTING` runs before TC egress, so `tc` mode
> cannot fail closed: if the qdisc or program disappears while the mode is `tc`,
> peer traffic leaves in the clear. The helper orders attach/mode and
> mode/detach, and `torshield-tc watch -i DEV` reverts the mode when the
> classifier disappears; a supervisor is still required. See
> [`../../TUN-HYBRID.md`](../../TUN-HYBRID.md) §5.

## Known limitations

- One static 256-bit PSK; no handshake, no forward secrecy, no rekeying.
- DoS: every framed packet still costs a Poly1305 check by default. An optional
  per-source fixed-window limiter (`ts_rl_pps`, default 0 = off) rejects over-limit
  packets before `skb_linearize`/authentication and counts them as `tun_rlimit`.
  It is not a cookie challenge.
- The peer list, key and mode are global module state shared across namespaces.
- Cryptokey routing supports distinct inner/outer addresses and endpoint roaming;
  multipath/ECMP is not implemented.
- TC mode is **fail-open** if the classifier disappears (`POST_ROUTING` precedes
  TC egress); the AEAD cannot run in BPF and stays in `ndo_start_xmit`.
- No PMTU discovery or ICMP relay; TCP MSS is clamped, large UDP relies on
  outer fragmentation/reassembly (verified to 60 KB). The receiver linearizes a
  reassembled skb before the AEAD, so a very large datagram needs a high-order
  atomic allocation and is dropped if it fails.
- Device path is egress-only; ingress is still the netfilter decap.
- Stream mode (legacy) has no integrity and is not the default.

## Files

- `torshield.c` — the kernel module
- `torshieldctl.c` — userspace control tool
- `Makefile` — builds both
- `tc/torshield_tc.c` — clsact/eBPF classifier
- `tc/torshield_tc_load.c` — `torshield-tc` libbpf loader/attacher
- `tc/Makefile` — builds the BPF object and the loader

Project-level results and the evidence log: [`../../README.md`](../../README.md),
[`../../TO-DO.md`](../../TO-DO.md), [`../../TUN-HYBRID.md`](../../TUN-HYBRID.md).
