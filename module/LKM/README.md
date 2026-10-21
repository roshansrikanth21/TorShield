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
| `stream` | legacy | Length-preserving payload transform, retained for comparison; **no integrity/authentication** |

## Crypto and framing

- **ChaCha20-Poly1305** (RFC 7539), synchronous, using the in-kernel ChaCha20
  helper plus a Poly1305 implementation, because `gcm(aes)` is async and cannot
  be used from softirq context.
- Wire format: `outer IP | UDP:4789 | 16-byte header | padded ciphertext | 16-byte tag`.
  The header is the AAD; the nonce is a 4-byte XOR fold of the outer addresses
  followed by the 64-bit big-endian sequence number.
- Plaintext is zero-padded to 64-byte buckets; the inner header determines the
  real length after decryption.
- Replay window: 64 packets per peer, advanced only after successful
  authentication.
- Outer IPv4 packets get a per-packet IP ID so fragmented datagrams are safe.

## Build

Requires kernel headers for the running kernel and a C toolchain:

```bash
sudo apt-get install -y build-essential linux-headers-$(uname -r)
make                       # builds torshield.ko and torshieldctl
```

Verified clean (`make W=1`) on 6.8.0-147 and 6.17.0-42.

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

## Known limitations

- One static 256-bit PSK; no handshake, no forward secrecy, no rekeying.
- DoS: any source can make the receiver perform a Poly1305 check (no cookie or
  rate limit before authentication).
- The peer list, key and mode are global module state shared across namespaces.
- No PMTU discovery or ICMP relay; TCP MSS is clamped, large UDP relies on
  outer fragmentation/reassembly (verified to 60 KB). The receiver linearizes a
  reassembled skb before the AEAD, so a very large datagram needs a high-order
  atomic allocation and is dropped if it fails.
- Hybrid uses **inner == outer** addressing in the prototype; distinct tunnel
  addresses need an endpoint mapping and policy routing.
- Stream mode (legacy) has no integrity and is not the default.

## Files

- `torshield.c` — the kernel module
- `torshieldctl.c` — userspace control tool
- `Makefile` — builds both

Project-level results and the evidence log: [`../../README.md`](../../README.md),
[`../../TO-DO.md`](../../TO-DO.md), [`../../TUN-HYBRID.md`](../../TUN-HYBRID.md).
