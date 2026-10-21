# TorShield — Master To-Do & Evidence Log

**Owner:** V. S. Roshan · **Started:** 2026-10-21 · **Last update:** 2026-10-21
**Canonical code:** `module/LKM/torshield.c` (v4 — stream mode **and** UDP tunnel mode).
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
| **D1: datapath** | **RESOLVED — option B (UDP tunnel)**, now the default mode |
| Stream mode (legacy, opt-in) | **DONE** — TCP/UDP v4+v6 integrity verified; no AEAD by construction |
| **Tunnel mode: AEAD + padding + seq + replay** | **DONE** — ChaCha20-Poly1305, 64-byte buckets, 64-packet window |
| Tunnel integrity (v4 1 MB, v6 256 KB) | **DONE** — 100% byte-exact, independent AEAD verification |
| Tunnel replay / tamper / non-peer | **DONE** — all dropped, counters exact |
| Tunnel control plane | **DONE (procfs)** — mode, key, peers, stats |
| **Hybrid TUN networking** | **DONE (prototype)** — `torshield0` netdevice, v4 + v6 verified |
| CI, docs, paper | **TODO** (P2/P3) |

**Critical correction to earlier claims:** before this session the module silently left bulk
TCP **unencrypted** (GSO path) or, with TSO off, **corrupted 98.8% of the stream**. Both are
fixed and regression-tested now. Any throughput number measured before today (including the
1266 Mbps figure in `CONTEXT.md`) was measured on a path that was not encrypting.

---

## B. Decision gates — needed from Roshan

### D1 — Transparent stream (A) or UDP tunnel (B)?  **RESOLVED: B**

**Decision: B — UDP tunnel** is now the default (`ts_mode = TS_MODE_TUNNEL`). The stream
transform is retained as an opt-in mode via `/proc/torshield/mode` for comparison and for the
measurement study; it is no longer the default.

Rationale (and why A cannot carry AEAD): the stream transform is *length-preserving* — same
packet size on the wire. AEAD adds a 16-byte tag and padding adds up to a bucket size, and TCP
sequence numbers count payload bytes, so a transparent TCP transform cannot add bytes without
terminating TCP. Only the tunnel can have real authentication, padding, a packet counter nonce
and a replay window. Tunnel wire format:

```
outer IP | UDP:4789 | 16-byte header ('T','S',ver,flags,seq) | padded ciphertext (64-byte buckets) | 16-byte tag
AAD = header · nonce = XOR-folded (src,dst) || 64-bit BE seq · ChaCha20-Poly1305 (RFC 7539)
```

The AEAD is synchronous by design: the in-kernel ChaCha20 helper plus a hand-written Poly1305
are used because `gcm(aes)` is `async: yes` and cannot be used from softirq context.

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

## D2. Tunnel datapath (D1 = B) — implementation and defects found by testing

**Architecture.** 6 netfilter hooks per network namespace (registered with
`register_pernet_subsys`): IPv4/IPv6 × PRE_ROUTING/POST_ROUTING/LOCAL_IN.

* **Egress** — `NF_INET_POST_ROUTING` (last): if the destination is a configured peer, the
  packet is stolen, fragmented (GSO) per segment, padded, encrypted, wrapped in UDP:4789 and
  sent with `ip_local_out`/`ip6_local_out`. Outer packets are recognised by port and skip the
  hook (no recursion).
* **Ingress** — `NF_INET_LOCAL_IN` (first, after IP reassembly): parse header, look up the peer
  by source address, verify AEAD, check replay window, decrypt, re-inject with `netif_rx`
  (`skb->mark = TS_TUN_MARK`).
* **Fail-closed**: any error in tunnel mode drops the packet, unlike stream mode (fail-open).
* **MSS clamp**: 1360 (v4) / 1340 (v6) so the outer packet never exceeds 1500.
* **Replay window**: 64 packets per peer, advanced **after** successful authentication.
* **Link scope guard**: IPv6 link-local/site-local/loopback and IPv4 169.254/127 sources are
  never tunneled (they are link-scoped; tunneling them is meaningless).

**Defects found by testing during bring-up (all fixed):**

| # | Symptom | Root cause | Fix |
|---|---|---|---|
| D2.1 | Every packet failed authentication (`tun_in 0`, `tun_drop` climbing) | Poly1305 tag computed over the **plaintext** before encryption | Encrypt first, then MAC the ciphertext (RFC 7539 order) |
| D2.2 | Kernel panic `skb_under_panic` in `tpacket_rcv` | Re-injected skb had `mac_header = 0xffff`; tcpdump's AF_PACKET tap computed a bogus `skb_push` | `skb_reset_mac_header()` on the decapped skb |
| D2.3 | Replay window could be advanced by unauthenticated packets | Replay check ran before AEAD verification | Authenticate first, then check/advance the window |
| D2.4 | 3 packets/run dropped as non-peer (`fe80::…`) | IPv6 neighbour advertisements to a peer address were encapsulated | Never tunnel link-local/site-local/loopback sources |

**Known limits of tunnel mode (honest list).** No rekeying or key rotation; no handshake or
cookie/DoS protection (any source can make the receiver do a Poly1305 check); the peer list is
global across netns; no PMTU discovery/ICMP relay; large inner UDP datagrams depend on outer IP
fragmentation and reassembly (not yet tested); single shared PSK.

---

## E. P2/P3 — remaining backlog

### P2 — Crypto & architecture
- [x] AEAD + tags — ChaCha20-Poly1305, tunnel mode (R24)
- [x] Per-packet sequence + 64-packet replay window (R25)
- [ ] Per-flow key derivation (HKDF) from a master secret
- [ ] Rekeying / key rotation and a handshake (currently one static PSK, no forward secrecy)
- [ ] DoS hardening: cheap cookie/rate limit before the Poly1305 check on decap
- [ ] Length-preserving MAC alternative for stream mode, or explicitly drop its integrity claim
- [ ] Fix TCP seq wrap in stream mode (rekey per flow at ~2 GB, or counter-based nonce)

### P2.5 — Hybrid TUN networking (prototype done, see `TUN-HYBRID.md`)
- [x] Virtual L3 netdevice (`torshield0`) with `ndo_start_xmit` reusing the tunnel AEAD/framing (R28)
- [x] Route-based steering (`ip route … dev torshield0`) instead of netfilter peer matching (R28)
- [x] Underlay route lookup pinned to `IFLA_LINK`, with a recursion guard (R29)
- [x] Coexistence: netfilter skip for packets routed into a `torshield` device (`TS_MODE_HYBRID`)
- [x] Interop test: netfilter-transparent peer ↔ TUN peer on the same wire format (R29/R30)
- [ ] Receive path: deliver decapped packets through the tunnel netdevice (today: stack inject)
- [ ] Decide inner-vs-outer address model (same address today; separate tunnel/underlay
      addresses + endpoint mapping are needed for a general route-based deployment)
- [ ] Advertise GSO/TSO and segment in the driver (currently no offloads; stack segments to MTU)

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
| R21 | Tunnel: `make W=1`, 6.8.0-147 + 6.17.0-42 | **PASS** — clean, 0 source warnings |
| R22 | Tunnel: TCP 1 MB over n1↔n2 (default mode) | **1048576/1048576 correct (100%)**; 1054 tunnel frames, 1054 valid headers, 0 bad padding, 0 plaintext bytes |
| R23 | Tunnel: IPv6 TCP 256 KB | **262144/262144 correct (100%)** |
| R24 | Independent AEAD verification — `verify_tunnel.py` (python-`cryptography` 46.0.6) decrypts the on-wire capture | **1054/1054 authenticated**; inner SYN MSS **1360**; frame = outer IP + UDP:4789 + 16-byte header + 64-byte-bucket ciphertext + 16-byte tag |
| R25 | Replay / tamper / unknown peer (stage16 §4 + stage17) | replay dropped (`tun_replay 1`), tampered new sequence dropped (`tun_drop 1`), framed packet from unknown source dropped (`tun_peer 1`); final `tun_rx = tun_in + 2` exactly; no kernel oops/panic |
| R26 | Interop: tunnel packet built by an independent Python ChaCha20-Poly1305 sender (`inject.py`) | **accepted and delivered** (`RX b'FROM-PYTHON'`, `tun_in` +1) — format and nonce/AAD agree in both directions |
| R27 | Regression for D2.4: IPv6 neighbour advertisements (src `fe80::…`) | no longer encapsulated; `tun_peer 0` (was 3 per run before the link-scope guard) |
| R28 | Hybrid: `ip -n n1 link add name torshield0 link veth1 type torshield` + `ip route add 10.0.0.2/32 dev torshield0`, mode `hybrid` | device created (`rc=0`, MTU 1360, `noqueue`); small TCP marker `HYBRID_OK`; `dev_out 5`, `dev_drop 0` |
| R29 | Hybrid: TCP 1 MB through `ndo_start_xmit` (n1 device → n2 netfilter decap; n2 replies via netfilter) | **1048576/1048576 correct (100%)**; 807 outer frames, 807 valid headers, 0 bad padding, 0 plaintext; **807/807 authenticated** by `verify_tunnel.py`; inner SYN MSS **1320**; totals `dev_out 1020`, `dev_drop 0`, `tun_out 173` (both datapaths in one run) |
| R30 | Hybrid: IPv6 TCP 256 KB through `ndo_start_xmit` | **262144/262144 correct (100%)**; 208 outer frames, 208 valid headers, 0 bad padding; **208/208 authenticated** (`ver=6`) |
| R31 | Defect found by testing: IPv6 router solicitations (48-byte ICMPv6, dst `ff02::2`) reached `ndo_start_xmit` and were counted as malformed (`dev_drop 3–5/run`) | fixed with a multicast/link-local guard; `dev_drop 0` |

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
* Stream-mode tests: `.work/vm-src/stage{1..15}.sh`, pcap analyser `.work/vm-src/pcap.py`.
* Tunnel tests: `.work/vm-src/stage16.sh` (acceptance: build, load, TCP v4/v6, UDP,
  replay, tamper) and `.work/vm-src/stage17.sh` (replay/tamper/unknown-peer/interop).
  Hybrid device test: `.work/vm-src/stage18.sh` (device creation, v4 + v6 through
  `ndo_start_xmit`, coexistence with the netfilter path).
  Independent checks: `verify_tunnel.py` (decrypts the capture with python-`cryptography`),
  `inject.py` (builds tunnel packets from scratch), `replay.py` (replays captured frames).

---

## H. Known limitations (honest list, for the paper)

**Tunnel mode (default):**

1. **Static single PSK** — no handshake, no rekeying, no forward secrecy.
2. **No DoS protection** — every framed packet costs a Poly1305 verification before the replay
   check, so an off-path sender can force crypto work.
3. **Peer = IP address only**, and one peer list is shared by every network namespace.
4. **No PMTU discovery or ICMP relay.** Inner TCP is MSS-clamped; large inner UDP datagrams rely
   on outer IP fragmentation and reassembly (not yet tested).
5. **Outer UDP checksum is 0 over IPv4** (legal; integrity comes from the AEAD tag).
6. **Throughput** measured only on emulated hardware (TCG).

**Stream mode (opt-in, legacy):**

7. **No authentication** — a modified ciphertext is accepted (stream cipher only); no replay protection.
8. **Fragmented traffic is not obfuscated** (passes intact, plaintext); IPv6 extension headers are skipped.
9. **TCP seq wrap** (>4 GB on one connection) reuses the keystream.
10. **No padding/shaping** — packet sizes and timing are unchanged, so the traffic is still
    fingerprintable; the original README claim that rotation defeats statistical analysis is false.

**Both modes:**

11. Control plane is procfs, not netlink; no kill switch/dry-run/safe mode.
12. No real-hardware throughput numbers yet.

**Hybrid (TUN netdevice) prototype — see `TUN-HYBRID.md`:**

13. **Same inner/outer addresses**; no endpoint mapping or policy routing yet, so overlapping
    inner prefixes cannot be supported.
14. **No offloads on the device** (no GSO/TSO); the stack segments to the 1360-byte MTU.
15. Mode is **global**, not per-netns; ingress is still injected by the netfilter decap rather
    than delivered through the tunnel device (so `rp_filter`/policy routing do not see it).

---

## I. Open questions for Roshan

1. **"Shift the hooks to target the socket buffer"** — this is ambiguous: netfilter hooks already
   receive an `sk_buff`. Did you mean (a) TC clsact/eBPF on `sk_buff`, (b) kprobes on
   `tcp_sendmsg`/socket-level functions, (c) a netfilter hook that works on skb head/sg data
   directly (which is what the tunnel now does), or (d) an explicit virtual netdevice?
2. **Hybrid TUN** — interpretation confirmed and implemented: a kernel virtual L3 interface
   (`torshield0`) steered by routes, reusing the UDP AEAD framing (`TUN-HYBRID.md`). Remaining
   design question: keep inner == outer addresses (current prototype), or add distinct tunnel
   addresses + an endpoint mapping for overlapping inner prefixes?
3. **D3** — is the QEMU VM acceptable, or do you want `kalix0`/`meoww` (need login)?
4. **D4** — paper: measurement-study framing confirmed? The 1266 Mbps figure must be withdrawn.
5. **Authorship** — confirm the author line with the professor before publishing.
