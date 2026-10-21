# TorShield — Project Context & Handoff

This folder is a complete handoff of the TorShield work: the research paper, the
rewritten kernel module, the test harness, and the original code for reference.
Read this file first — it explains what the project is, what was wrong, what was
fixed, the real measurements, and what's still left to do.

> **Status note (2026-10-21): partly superseded.** This document is the handoff
> from the v3 stream-mode rewrite. The module is now **v4**: the default datapath
> is an **authenticated UDP tunnel** (ChaCha20-Poly1305), plus an optional hybrid
> TUN netdevice. The speed numbers in §5 are **withdrawn** (they were measured on
> a path that was not encrypting). For current behaviour, verified results and
> open work, read [`README.md`](README.md) and [`TO-DO.md`](TO-DO.md); for the
> hybrid design, [`TUN-HYBRID.md`](TUN-HYBRID.md).

---

## 1. What TorShield is

TorShield is a **Linux kernel module** that obfuscates network traffic by
encrypting the **payload** of TCP/UDP packets in the kernel, transparently, via
the Netfilter hooks. Two machines running it with the same key can talk; the
data is scrambled on the wire. It is **obfuscation to defeat basic inspection /
DPI**, not a full security solution (no header protection, no metadata hiding).

- Original author: Yash Yashuday (senior). Supervisor: Dr. S. UdhayaKumar,
  Amrita Vishwa Vidyapeetham.
- This work was taken over by **V. S. Roshan** (roshansrikanth21@gmail.com).
- Original code repo: https://github.com/HeathKnowles/TorShield

---

## 2. Original state and the problems found

The handed-over paper (`original paper`, a PDF→Word of a LaTeX doc) and the repo
(`original_repo/`) **did not match**, and both had serious problems:

**Design / code bugs (original `xor_obfuscation.c`):**
- Only hooked `NF_INET_POST_ROUTING` (egress) — **never decrypted inbound
  traffic**, so two hosts could not actually communicate. The paper's
  "end-to-end" and "bidirectional" claims were impossible with this code.
- IPv4 only.
- XOR'd **all** TCP/UDP traffic — would break DNS, TLS, loopback, etc.
- Set `CHECKSUM_NONE` but **never recomputed the checksum** → most NICs send
  bad checksums → receiver drops the packets.
- Independent `(key+17) % 256` rotation on each host → the two ends desync.
- `printk` on **every packet**, logging src/dst IPs — destroys throughput and
  leaks the very metadata it claims to protect.
- `/proc/xor_key` was mode `0666` (any user could read/set the key).
- Single-byte XOR: 256 possible keys, trivially broken.

**Paper problems:**
- Fabricated results: "+1% CPU", "0.5 ms/packet", "−5% throughput" — not
  reproducible from any code, and the 0.5 ms figure is ~400× too high.
- Fig. 3 "screenshots" couldn't come from the real code (wrong log prefix,
  wrong rotation interval, wrong module name).
- Broken `Table ??` reference, thin/dated references, one unverifiable citation.

---

## 3. The paper (`paper/`)

`TorShield_IEEE.docx` / `.pdf` — reformatted to **IEEE conference style, 6
pages**, first author **V. S. Roshan** (Yash removed from the author line per
Roshan's decision — this should be confirmed with the professor as an
authorship-integrity matter).

Fixed: broken `Table ??`, Fig. 2 redrawn from real data, all **10 references
verified against primary sources and IEEE-formatted** (added WireGuard [9] and
the GFW fully-encrypted-traffic detection paper [10]), references numbered in
order of first citation, last-page columns balanced.

**NOT yet done in the paper:** the technical content still describes the
*original* single-byte XOR, one-directional design, and still carries the old
"minimal impact" performance claims. Table I and Fig. 2 need to be replaced with
the **real measured numbers** (see §5), and the text should be reframed honestly
as a measurement study. (The paper was built with a docx-js script that lives in
the Claude session scratchpad, not in this folder — regenerating it means
re-editing in Word or rebuilding that script.)

---

## 4. The rewritten module (`module/LKM/`)

Complete rewrite. **Current version: 4.0 (AEAD tunnel; v3 was the ChaCha20
stream transform).** Every original bug above is fixed:

> The bullets below describe the v3 stream-mode transform, which is now an
> opt-in mode. The **default** v4 datapath is a UDP tunnel with
> ChaCha20-Poly1305, padding, sequence numbers and a replay window, in which
> the v3 rule "no integrity/authentication" no longer applies. See
> [`README.md`](README.md) and [`TUN-HYBRID.md`](TUN-HYBRID.md).

- **Bidirectional:** hooks both `POST_ROUTING` (encrypt) and `PRE_ROUTING`
  (decrypt). Registered **per network namespace** (`register_pernet_subsys`), so
  it works in netns testbeds / containers, not just `init_net`.
- **IPv4 + IPv6, TCP + UDP.**
- **Peer allowlist:** only traffic to/from configured peer IPs is touched; the
  module is **inert until a key and ≥1 peer are set**, so loading it never
  breaks the box.
- **Correct checksums:** full software recompute after modifying the payload;
  hardware-offload (`CHECKSUM_PARTIAL`) packets are left to the NIC.
- **Real cipher — ChaCha20 (RFC 8439)** via the kernel crypto library
  (`<crypto/chacha.h>`), the same cipher WireGuard uses. Replaced the weak XOR.
  (History: v2 used a SipHash-derived keystream XOR; v3 upgraded to ChaCha20.)
- **256-bit pre-shared key** set via `/proc/torshield/psk` (64 hex chars).
- **Per-packet nonce** derived from header fields both ends see (addresses,
  ports, TCP sequence number; UDP uses IP ID + length, which is weaker). No
  time-window rotation anymore — the nonce provides uniqueness.
- **No per-packet logging**, key never logged, `/proc/torshield/*` config files are
  mode `0600` (root only); `stats` is read-only `0444`.

**Control tool:** `torshieldctl` — `set-key <64hex>`, `add-peer <ip>`,
`del-peer`, `list-peers`, `clear-peers`, `status`.

**Verified:** compiles cleanly (`make W=1`, `gcc -Wall -Wextra`) against Linux
6.8 and 6.17 kernel headers. See `module/LKM/README.md` for modes, usage and
current limitations. Note that the v3 text above predates the v4 AEAD tunnel;
the stream mode's nonce caveats and lack of integrity apply only to the legacy
`stream` mode, not to the default tunnel.

---

## 5. Test results (`module/test/`)

**Userspace self-test** (`ts_selftest.c`, no root) — reimplements ChaCha20 +
checksum and validates properties. **All pass**: round-trip, keystream =
f(key,nonce), checksum validity. (Its ChaCha20 microbenchmark uses a scalar
reference and is not representative; the kernel's SIMD ChaCha20 is faster.)

**Network-namespace testbed** (`run_testbed.sh`, needs root; `torshield_testbed.sh`
is a self-contained single-file version). Run on Roshan's Ubuntu 24.04 VM.

Results from the **v2 (keystream-XOR) build** — **WITHDRAWN, do not cite.** These
numbers were measured on a path that was not actually encrypting (the GSO bug left
bulk TCP in plaintext), so they do not measure TorShield at all:

| Metric            | Without TorShield | With TorShield | Change |
|-------------------|-------------------|----------------|--------|
| TCP throughput    | ~~2392 Mbps~~     | ~~1266 Mbps~~  | withdrawn |
| UDP throughput    | ~~1361 Mbps~~     | ~~713 Mbps~~   | withdrawn |
| UDP loss          | ~~0.19%~~         | ~~0.26%~~      | withdrawn |

Correctness (all **PASS**): module loads, ICMP reaches peer, **TCP payload
delivered intact**, **marker NOT in cleartext on the wire** (payload is
obfuscated), bidirectional.

**Current status:** no valid throughput number exists yet. What has been verified
on v4 is correctness: 1 MB IPv4 and 256 KB IPv6 delivered byte-exact, every
captured frame authenticated by an independent ChaCha20-Poly1305 implementation,
replay/tamper/unknown-peer dropped with exact counters, 4 KB and 60 KB UDP
datagrams intact across outer fragmentation, and the hybrid TUN path at 100%.
See `README.md` §Verified results and `TO-DO.md` §F for the evidence log.

The headline is honest: **the module works and the tunnel authenticates correctly,
but no real-hardware overhead measurement has been made, and the original paper's
"minimal impact" claim remains unsupported.**

---

## 6. Is it worth publishing?

- **Not** for a top security venue (USENIX/CCS/NDSS/PETS) — weak novelty and
  limited security: the tunnel has AEAD, but a static PSK with no handshake,
  no forward secrecy and no metadata protection leaves it far below WireGuard,
  and no real-hardware overhead measurement exists yet.
- **Yes**, publishable at a **student / regional IEEE / workshop** level **if
  reframed honestly as a measurement/systems study** ("what transparent
  kernel-level obfuscation costs and what it actually defeats"), not as a privacy
  solution. The strongest version would compare XOR vs ChaCha20 vs WireGuard
  against real DPI/ML classifiers, and add a userspace (NFQUEUE) vs kernel
  overhead comparison.

---

## 7. Open TODO (for whoever picks this up)

1. **Measure v4 throughput on real hardware** (KVM or physical, with and without
   GSO) → get true tunnel throughput/CPU numbers for §5. Never reuse the
   withdrawn 1266 Mbps figure.
2. **Update the paper**: replace Table I + Fig. 2 with the real numbers; rewrite
   the abstract/performance/functionality sections to match the v4 AEAD tunnel
   and honest overhead; drop the fabricated multi-distro / 72-hour / "minimal
   impact" claims.
3. **Confirm authorship** of Yash with the professor.
4. (Optional, strengthens the paper) Build a **userspace NFQUEUE** variant for a
   kernel-vs-userspace overhead comparison; test against nDPI/Zeek/Suricata and
   an ML classifier.
5. Known v4 limitations to note or address: static PSK with no handshake/rekeying;
   no DoS cookie before the Poly1305 check; peer/key/mode configuration is global
   across namespaces; no PMTU discovery; hybrid prototype uses inner == outer
   addressing (see `TUN-HYBRID.md` §2.4); the legacy stream mode still has no
   integrity and a TCP sequence wrap limit.

---

## 8. File map

```
CONTEXT.md                     ← this file (historical handoff; see status note)
README.md                      ← current modes, build, verified results, limits
TO-DO.md                       ← master tracker + evidence log R1–R35
TUN-HYBRID.md                  ← hybrid TUN design and verified results
paper/
  TorShield_IEEE.docx / .pdf   ← 6-page IEEE paper (formatting/citations fixed;
                                  content still needs the real numbers)
module/
  LKM/
    torshield.c                ← the rewritten kernel module (v4, tunnel+hybrid)
    torshieldctl.c             ← userspace control tool
    Makefile
    README.md                  ← modes, build, usage, limitations
  test/
    ts_selftest.c              ← userspace correctness + microbench (no root)
    run_testbed.sh             ← legacy stream-mode netns testbed (needs root)
    run_selftest.sh
    README.md
  torshield_testbed.sh         ← legacy all-in-one testbed (embeds v2; not for numbers)
.work/vm-src/                  ← QEMU harness used for all v4 evidence
original_repo/                 ← the senior's original code, for reference/diff
  LKM/xor_obfuscation.c, xorctl.c, Makefile
  README.md
```
