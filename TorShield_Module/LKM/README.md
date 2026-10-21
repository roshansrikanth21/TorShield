# TorShield (kernel module, v2)

> **Frozen snapshot.** This tree is kept for the paper/handoff. The current
> module is [`module/LKM`](../../module/LKM) at the repository root. This copy
> predates the v4 AEAD tunnel and hybrid TUN datapaths, so its usage and
> limitations sections are out of date.

Bidirectional kernel-level traffic obfuscation for Linux, built on Netfilter.
This is a corrected rewrite of the original `xor_obfuscation` module. It is a
research/teaching artifact, **not** a replacement for real encryption
(WireGuard, TLS, IPsec).

## What changed from the original

| Problem in the original | Fix in v2 |
|---|---|
| Only hooked `POST_ROUTING` (egress) — the receiver never decrypted, so two hosts could not actually talk | Hooks both `POST_ROUTING` (encrypt) and `PRE_ROUTING` (decrypt) |
| IPv4 only | IPv4 **and** IPv6 |
| XOR'd *all* TCP/UDP traffic — broke DNS, TLS, loopback, one-sided/gateway use | Only touches traffic to/from an explicit **peer allowlist**; inert until peers are set |
| Set `CHECKSUM_NONE` but never recomputed the checksum — most NICs send bad checksums, receiver drops them | Recomputes the full transport checksum in software; leaves hardware-offload (`CHECKSUM_PARTIAL`) packets to the NIC |
| Each host rotated the key independently (`key = (key+17) % 256`), so the two ends desynced | A static 256-bit pre-shared key plus a **per-packet nonce** derived from header fields both ends see; no coordination needed |
| `printk` on **every packet**, logging src/dst IPs — wrecks throughput and leaks the metadata it claims to protect | No per-packet logging; key material never logged |
| `/proc/xor_key` was mode `0666` (any user could read/set the key) | `/proc/torshield/*` are mode `0600` (root only); the key is never read back |
| `del_timer` on unload (timer could fire after free) | No timers; the keystream is a pure function of (key, nonce) |
| Single-byte XOR (256 possible keys) | **ChaCha20** (RFC 8439) via the kernel crypto library — a real, fast, length-preserving stream cipher (the one WireGuard uses) |

## Build

Requires kernel headers for the running kernel and a C toolchain:

```bash
sudo apt-get install -y build-essential linux-headers-$(uname -r)
make                       # builds torshield.ko and torshieldctl
```

Verified to compile cleanly (`make W=1`, `gcc -Wall -Wextra`) against Linux 6.8.

## Usage

On **both** hosts, with the same pre-shared key:

```bash
sudo insmod torshield.ko
# 64 hex chars = 256-bit ChaCha20 key (same on both hosts)
sudo ./torshieldctl set-key 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
sudo ./torshieldctl add-peer 10.0.0.2                          # the other host
sudo ./torshieldctl list-peers
sudo ./torshieldctl status                                     # "set" / "unset"
```

The module stays inert until a PSK **and** at least one peer are configured, so
loading it never disrupts the box. Remove and unload:

```bash
sudo ./torshieldctl clear-peers
sudo rmmod torshield
```

`/proc/torshield/psk` · `peers` are the raw interfaces; `torshieldctl` is a
thin wrapper over them.

## Known limitations

- **Nonce derivation, not negotiation.** ChaCha20 needs a unique nonce per
  packet. Since the packet length can't grow to carry one, the nonce is
  derived from header fields both ends see: addresses, ports, and the TCP
  sequence number (for UDP, the IP ID + length, which is weaker). A TCP
  retransmission reuses the nonce but carries the same plaintext, which is
  safe; the residual risks are TCP sequence-number wrap (>4 GB on one
  connection) and the narrow UDP nonce space. A production design would
  negotiate a per-packet nonce or key id out of band.
- **No integrity or authentication.** This is encryption of the payload only,
  not an AEAD tunnel. It defeats signature-based DPI and passive inspection,
  not flow-feature ML classifiers, entropy analysis, or an adversary who can
  tamper with packets.
- **Packet headers are untouched**, so size, timing, and endpoints remain
  visible.
- **GSO packets and IPv6 extension headers are passed through unmodified** (not
  obfuscated) to avoid corrupting them.
- Config (`/proc/torshield`) is **global module state** shared across network
  namespaces; the hooks themselves run in every namespace.

## Files

- `torshield.c` — the kernel module
- `torshieldctl.c` — userspace control tool
- `Makefile` — builds both
