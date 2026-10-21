# TorShield — Master To-Do & Evidence Log

**Owner:** V. S. Roshan · **Started:** 2026-10-21 · **Last update:** 2026-10-21
**Canonical code:** `module/LKM/torshield.c` (v3, ChaCha20).
The Notion plan was written against `original_repo/LKM/xor_obfuscation.c`; most Phase 0–3
items were already implemented in v3, so they are marked as such below instead of redone.

**Rule:** nothing is marked `DONE` without a reproducible command + captured output in §F.
Claims are labelled `BUILD-VERIFIED`, `RUNTIME-VERIFIED`, or `STATIC-ONLY`.

---

## A. Status at a glance

| Area | State |
|---|---|
| Build matrix (6.8 LTS + 6.17 HWE, `W=1`) | **DONE** — clean |
| Real-kernel test environment | **DONE** — QEMU Ubuntu 24.04, kernel 6.8.0-147 |
| TCP datapath (small + bulk, GSO on/off, v4 + v6) | **DONE** — integrity + ciphertext verified |
| UDP datapath (DF on/off, v4 + v6) | **DONE** — keystream reuse eliminated |
| Fragments | **DONE (fail-open)** — intact, but not obfuscated (documented) |
| Malformed headers | **DONE (fail-open)** — verified with a doff=0 packet |
| Module load dependency | **DONE** — `MODULE_SOFTDEP`, `modprobe` verified |
| AEAD / padding / replay protection | **BLOCKED on decision D1** |
| Control plane, CI, docs, paper | **TODO** (P2/P3) |

**Critical correction to earlier claims:** before this session the module silently left bulk
TCP **unencrypted** (GSO path) or, with TSO off, **corrupted 98.8% of the stream**. Both are
fixed and regression-tested now. Any throughput number measured before today (including the
1266 Mbps figure in `CONTEXT.md`) was measured on a path that was not encrypting.

---

## B. Decision gates — needed from Roshan

### D1 — Transparent stream (A) or UDP tunnel (B)?  *(blocks P2/P3)*

The module is *length-preserving*: same packet size on the wire. That is exactly why AEAD and
padding cannot be added on the TCP path:

* AEAD adds a 16-byte tag; padding adds up to a bucket size.
* TCP sequence numbers count payload bytes. Injecting bytes desynchronises the stream, ACKs
  and retransmissions. A transparent TCP transform cannot add bytes without terminating TCP.

**A. Stay transparent** — ChaCha20 stream, length-preserving, no AEAD, no padding. Honest paper:
measure the cost and the limits. *(This is what is now correct and tested.)*

**B. Tunnel** — encapsulate the inner packet in UDP, then AEAD + padding + counter nonce +
replay window are all correct and simple. It becomes a VPN/tunnel, not transparent obfuscation.

**Recommendation:** B for real anti-DPI value; A for the current paper. Not both.

### D2 — Target kernels
Confirmed by testing: 6.8.0-147 (Ubuntu 24.04 LTS) and 6.17.0-42 (HWE). Mainline compile
checks are possible too. Tell me if the college machines run something else.

### D3 — Test host
Built and working: QEMU (TCG, no KVM) Ubuntu 24.04 inside WSL2, SSH on `127.0.0.1:2222`.
No root, no VirtualBox login needed. Numbers from it are **relative only** (emulated CPU);
real-hardware numbers still need a physical/VM host with KVM.

### D4 — Paper framing
Confirm the measurement-study framing (`CONTEXT.md`). The old numbers must be withdrawn.

---

## C. P0 — Build & hygiene  *(DONE)*

| ID | Task | State | Evidence |
|---|---|---|---|
| T0.1 | Build on 6.8.0-147 headers | DONE | R1, R6 |
| T0.2 | Build on 6.17.0-42 (ChaCha API changed in 6.16) | DONE — version-conditional `struct chacha_state` | R2 → R6 |
| T0.3 | `-Wall -Wextra -Wno-unused-parameter`, zero source warnings | DONE | R6 |
| T0.4 | `make W=1` clean | DONE | R7 |
| T0.5 | Makefile: `$(CURDIR)`, `.PHONY`, `install`/`uninstall`/`modules_install` | DONE | R6 |
| T0.6 | `.gitignore` | DONE | file |
| T0.7 | Load dependency on `chacha_x86_64` | DONE — `MODULE_SOFTDEP("pre: chacha_x86_64")`, `modprobe` verified | R16 |

Legacy `original_repo` builds on 6.8 but not on ≥6.15 (`del_timer` removed). Kept only as the
"before" artifact; not shipped.

---

## D. P1 — Datapath correctness  *(all verified in the VM)*

| ID | Defect found by testing | Fix | Evidence |
|---|---|---|---|
| T1.1 | **GSO/TSO super-skbs skipped** → bulk TCP encrypted **nothing** (TSO on) or, with TSO off, ingress "decrypted" plaintext segments → **98.8% of the stream corrupted** while TCP accepted it (module rewrites checksums). | Encrypt per `gso_size` chunk with nonce `seq + offset`; leave segmentation to the stack. | R9, R10 |
| T1.2 | **Fragments corrupted**: egress encrypted the pre-fragmentation datagram, ingress skipped the fragments. | Skip egress datagrams that exceed the MTU **and** ingress fragments; fragmented traffic stays plaintext but intact. | R11, R12 |
| T1.3 | **No `ihl`/`doff` validation** → header bytes could be encrypted. | `ihl >= 5`, `doff >= 5`, `tot_len`/`payload_len` checks. | R13 (doff=0 passes untouched) |
| T1.4 | **UDP keystream reuse (CRITICAL)**: with DF set Linux leaves IP ID = 0, so every same-size datagram reused the same nonce. Proven mathematically: `C1⊕C2 == P1⊕P2`. | Stamp a per-packet counter into the IPv4 ID (fix IPv4 header checksum) and the IPv6 flow label; nonce from that. | R8 (before), R11/R14 (after: no reuse) |
| T1.5 | TCP nonce = seq; wrap at 4 GB reuses the keystream. | Not fixed; documented limit. | STATIC |
| T1.6 | Fail-open | Implemented and verified for malformed, fragments, GSO-UDP, crypto errors. | R12, R13 |
| T1.7 | IPv6 extension headers → packet skipped (plaintext). | Documented; no fix yet. | STATIC |
| T1.8 | Peer config is global (all netns) and IP-only (no ports). | Documented; P2. | STATIC |
| T1.9 | `psk_set` read without synchronisation. | `READ_ONCE`. | R15 |
| T1.10 | Checksum offload path (`CHECKSUM_PARTIAL` on GSO egress) only tested on veth. | Needs a real NIC/virtio peer test. | TODO |

### Notion-plan claims that did **not** reproduce

| Notion item | Verdict |
|---|---|
| 1.2 "OOB write because payload is written at `ip_hdr + data_offset` (14-byte Ethernet offset)" | **Not reproduced.** In netfilter hooks `skb->data == ip_hdr(skb)`; the MAC header is already pulled. The 14-byte assumption is wrong. Runtime non-linear-skb test still TODO, but no OOB path was found in review. |
| 1.3 "unsigned underflow → OOB" | **Downgraded.** Underflow yields a huge `payload_len`, which the `<= 65535` guard rejects. It was dead code, not an exploit. Now moot (explicit checks). |
| 2 "fix the `CHECKSUM_NONE` assignment" | Outdated: v3 sets `CHECKSUM_UNNECESSARY` after a full software checksum. The real GSO issue was the skip (T1.1). |

---

## E. P2/P3 — remaining backlog

### P2 — Crypto & architecture (blocked on D1)
- [ ] AEAD + tags (only possible in tunnel mode)
- [ ] Per-flow key derivation (HKDF) from a master secret
- [ ] Replay window / per-packet sequence
- [ ] Length-preserving MAC alternative for TCP mode, or explicitly drop the integrity claim
- [ ] Fix TCP seq wrap (rekey per flow at ~2 GB, or counter-based nonce)

### P3 — Operations, tests, docs
- [ ] Netlink control plane (replace procfs), kill switch, safe mode, dry-run
- [ ] netns integration harness committed to the repo (currently in `.work/vm-src/`)
- [ ] KUnit tests for length/parse arithmetic
- [ ] CI matrix (Ubuntu 22.04/24.04, Fedora, 6.8/6.17) + sparse/smatch
- [ ] Bypass list (loopback, multicast, DHCP, mDNS, NTP)
- [ ] Per-interface / per-netns policy
- [ ] README rewrite + threat model + SECURITY.md; withdraw the false claims
- [ ] Real-hardware throughput (KVM or physical), with and without GSO
- [ ] `torshield_testbed.sh` still embeds the **v2** SipHash module — do not use it for paper numbers

---

## F. Evidence log (append-only)

Environment: Ubuntu 24.04 cloud image, kernel `6.8.0-147-generic`, QEMU 8.2 TCG (no KVM),
2 vCPU. Module built with matching headers inside the VM.

| # | Command / test | Result |
|---|---|---|
| R1 | `make KDIR=…/6.8.0-147-generic` | **PASS** — `.ko` + `torshieldctl` |
| R2 | `make KDIR=…/6.17.0-42-generic` | **FAIL** — `chacha_init` expects `struct chacha_state *` (changed in 6.16) |
| R3 | `make` in `original_repo/LKM` @6.17 | **FAIL** — `del_timer` removed |
| R4 | `make` in `original_repo/LKM` @6.8 | **PASS** |
| R5 | QEMU/TCG Ubuntu 24.04 boot + SSH | **PASS** |
| R6 | Rebuild after ChaCha shim, both kernels, `-Wall -Wextra -Wno-unused-parameter` | **PASS**, 0 source warnings |
| R7 | `make W=1` both kernels | **PASS** |
| R8 | UDP 2×1000 B, DF set (before fix) | **keystream_reuse_proof=True**, IP ID 0 on both |
| R9 | 1 MB TCP, TSO on, before GSO fix | 100% delivered, **0 packets encrypted**, 0% ciphertext on wire |
| R10 | 1 MB TCP, TSO off, before GSO fix | **correct bytes 1.2%**, 98.8% corrupted; counters `gso_out 86`, `enc_out 6` |
| R11 | 512 KB TCP, TSO on, after GSO fix | correct **100%**, wire **0.0% plaintext**, `gso_out 25 / gso_in 25`, 0 skipped |
| R12 | 512 KB TCP, TSO off, after fix | correct **100%**, wire ciphertext, `enc_in 364` |
| R13 | 4000 B UDP, MTU 1500 after fragment fix | `received=4000 match=True`, `encrypted 0`, `skip_frag 4` |
| R14 | UDP 2×1000 B, DF on/off after nonce fix | IP ID 1,2 / 3,4; **keystream_reuse_proof=False**; content OK |
| R15 | malformed TCP `doff=0` | passed **untouched** (`MMMM…` on wire), `skip_bad 2` |
| R16 | `modprobe torshield` with `chacha_x86_64` unloaded | **rc=0**, auto-loaded `chacha_x86_64` |
| R17 | IPv6 TCP 256 KB | correct **262144/262144**, wire ciphertext, GSO handled |
| R18 | IPv6 UDP 2×1000 B | flow labels 1,2; **no reuse**; content OK |
| R19 | iperf3 TCP 5 s (TCG) | 446.0 Mbps baseline vs **58.1 Mbps** through TorShield, 0 retransmits |
| R20 | iperf3 UDP 50 M target (TCG) | 16.2 Mbps, 0% loss (emulated CPU bound) |

> R19/R20 are **not paper-grade**: TCG-emulated CPU. They show the direction and the overhead
> source (per-byte software ChaCha20 + linearise), not real-hardware numbers.

---

## G. Test environment / reproduction

```
WSL2 (no root) ── QEMU 8.2 TCG ── Ubuntu 24.04, 6.8.0-147-generic
   │                                   │
   ├─ ~/kernels/{6.8.0-147,6.17.0-42}  ├─ /home/ts/ts  (module source)
   ├─ ~/qemu/root                      ├─ netns n1/n2 + veth pair
   └─ ~/vm/noble.img                   └─ tcpdump + pcap.py analysis
```

* Build: `.work/rebuild.sh` (both kernels), `.work/build-w1.sh`.
* VM: `.work/launch-vm.sh`, SSH `ssh -p 2222 ts@127.0.0.1`.
* Tests: `.work/vm-src/stage{1..15}.sh`, pcap analyser `.work/vm-src/pcap.py`.

---

## H. Known limitations (honest list, for the paper)

1. **No authentication** — a modified ciphertext is accepted (stream cipher only).
2. **No replay protection.**
3. **Fragmented traffic is not obfuscated** (passes intact, plaintext).
4. **IPv6 extension headers are skipped** (plaintext).
5. **TCP seq wrap** (>4 GB on one connection) reuses the keystream.
6. **Peer = IP address only**; all ports and all netns share one config.
7. **No padding/shaping** — packet sizes and timing are unchanged, so the traffic is still
   fingerprintable; the original README claim that rotation defeats statistical analysis is false.
8. **Throughput** measured only on emulated hardware.
9. **`insmod` still fails without the chacha module** — use `modprobe`/`make install`.

---

## I. Open questions for Roshan

1. **D1** — transparent (A) or tunnel (B)? Everything in P2/P3 depends on it.
2. **D3** — is the QEMU VM acceptable, or do you want `kalix0`/`meoww` (need login)?
3. **GitHub** — the fork still has the senior's XOR code only. Pushing v3 needs your credentials;
   I can prepare commits/branches locally.
4. **D4** — paper: measurement-study framing confirmed? The 1266 Mbps figure must be withdrawn.
5. **Authorship** — confirm the author line with the professor before publishing.
