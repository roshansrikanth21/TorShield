# Claim-to-evidence audit for the IEEE manuscript

This file is the paper's evidence ledger. Every quantitative claim in
`TorShield_IEEE.tex` must appear here with a reproducible source. If a claim is
not in this file, it must not be in the paper.

The manuscript describes the **v4 tunnel/TC datapath** in
`module/LKM/torshield.c`, not the legacy single-byte-XOR prototype. The original
draft is preserved under `paper/archive/` and is not the evaluated system.

## Evidence status

| Status | Meaning |
|---|---|
| **VERIFIED** | Captured output exists in the repository or `.work` logs; the number in the paper matches it. |
| **VERIFIED, CAVEATED** | Captured, but the environment or scope is narrower than a production claim. The caveat is stated in the paper. |
| **NOT CLAIMED** | The draft asserted it, but the current system does not support it or it was not measured. Removed from the paper. |
| **NOT TESTED** | Implemented or buildable in principle, but no runtime evidence. The paper says so explicitly. |

## Claims in the manuscript

| Paper claim | Evidence | Status |
|---|---|---|
| ChaCha20--Poly1305, 16-byte header, 32-bit key id, 64-byte padding, 64-bit seq, 1024-packet replay window | `module/LKM/torshield.c` (`struct ts_tun_hdr`, `ts_aead_seal/open`, `ts_replay_ok`, `TS_REPLAY_WIN`) and `README.md` wire format | VERIFIED (code) |
| Key id is FNV-1a of the 32-byte key; zero selects the legacy global PSK | `ts_key_id_for()`, `peer_find_id_locked()`, `peers_show()` | VERIFIED (code) |
| Inner source ACL and authenticated endpoint roaming | `ts_peer_allows()`, `ts_tun_decap()` roaming block; R36 | VERIFIED |
| Netfilter egress at `POST_ROUTING`, ingress at `LOCAL_IN` after reassembly, ten hooks per netns | `fill_hook_ops()`, `ts_net_init()`, `README.md` | VERIFIED (code + runtime) |
| GSO segmentation and per-segment release | `ts_tun_out()` GSO loop; R47 | VERIFIED |
| MSS 1360 (v4) / 1340 (v6); device MTU 1360, MSS 1320 | `TS_TUN_MSS4/6`, `TS_DEV_MTU`, `TUN-HYBRID.md`; R29 | VERIFIED |
| Outer IPv4 ID is per packet | `ts_tun_encap_v4()`, `ts_ip_id`; D2.6 | VERIFIED |
| TC clsact/eBPF LPM steering + `TC_ACT_SHOT` when `cfg[0]` is unset | `module/LKM/tc/torshield_tc.c` (`steer()`), R37--R39 | VERIFIED |
| TC guard at `LOCAL_OUT`/`FORWARD`, uses `state->out`, accepts tun device or live TCX/cls_bpf | `ts_tc_guard()`, `ts_tc_egress_armed()`; R53/R54 | VERIFIED |
| TCX branch is compile-tested only | Build logs; runtime tests use clsact | NOT TESTED (runtime) |
| Loader reads all `allowed=` prefixes; peer add/del/clear forces `tunnel` | `torshield_tc_load.c`, `peer_change_leaves_tc()`; R56 | VERIFIED |
| Residual guard-to-egress race | `TUN-HYBRID.md` §5; code inspection | VERIFIED (design limitation) |
| Manual rekey with dual-key grace and explicit commit | `rekey-peer`/`rekey-commit`; R51 | VERIFIED |
| Per-source fixed-window limiter before `skb_linearize`/Poly1305 | `ts_ratelimit_ok()`, `ts_tun_decap()`; R44 | VERIFIED |
| Tunnel IPv4 TCP 1 MB byte-exact | R22; `stage16.sh` | VERIFIED |
| Tunnel IPv6 TCP 256 KB byte-exact | R23; `stage16.sh` | VERIFIED |
| Independent AEAD 1054/1054 frames | R24; `verify_tunnel.py` | VERIFIED |
| 4 KB and 60 KB inner UDP; 3 and 41 outer fragments | R32/R33; `stage19.sh` | VERIFIED |
| Replay/tamper/unknown-peer drops with exact counters | R25; `stage16.sh`/`stage17.sh` | VERIFIED |
| Hybrid IPv4 807/807 and IPv6 209/209 authenticated | R29/R35; `stage18.sh` | VERIFIED |
| Cryptokey routing v4 256/256, v6 64/64; ACL and roaming | R36; `stage20.sh` | VERIFIED |
| TC IPv4 256/256, `dev_out` 512; TC IPv6 64/64, `dev_out` 647 cumulative | R45; `native-stage21-final.log` | VERIFIED |
| TC wire v4 210/210 with per-peer key, 0/210 with global PSK | R39/R50 | VERIFIED |
| TC wire v6 68/68 with per-peer key, 0/68 with global PSK | R39 (QEMU); native v6 pcap empty | VERIFIED, CAVEATED |
| TC detach fallback 16/16 | R40/R45 | VERIFIED |
| `LOCAL_OUT` classifier deletion: 0 sent / 8 blocked, server 0, guard +8, dev_out +0, tun_out +0 | R53; `native-stage24-final2.log` | VERIFIED |
| `LOCAL_OUT` qdisc deletion: same | R53 | VERIFIED |
| Restore: 16/16; detach: 8/8 | R53 | VERIFIED |
| `FORWARD` no classifier: n2 ingress 8, n3 outer 0, guard +8, dev_out +0 | R54; `native-stage25-final2.log` | VERIFIED |
| `FORWARD` classifier present: guard +0, dev_out +8, n3 tun_rx +8 | R54 | VERIFIED |
| `FORWARD` classifier deleted: n3 outer 0, guard +8, dev_out +0 | R54 | VERIFIED |
| Peer add/del/clear forces tunnel | R56 | VERIFIED |
| Loader auto-fill 2 IPv4 + 2 IPv6 without `-4/-6` | R56 | VERIFIED |
| Rekey key id 4290739141 -> 1666914373; old+new accepted 4/4; post-commit old-key rejected as non-peer 1; tun_replay 0 | R51 | VERIFIED |
| Rate limiter at 50 pps: 950/1000 limited, 50 reach AEAD; echo 64/64 | R44 | VERIFIED |
| Baseline 4-stream 100.98/99.76/97.84 Gbit/s | R49 | VERIFIED, CAVEATED (WSL2/Hyper-V) |
| Tunnel 1-stream 909.7/921.5/965.4 Mbit/s | R49 | VERIFIED, CAVEATED |
| Tunnel 4-stream 3345.6/3018.1/3203.1 Mbit/s | R49 | VERIFIED, CAVEATED |
| 30 s sustained 3.40 Gbit/s; flat SUnreclaim 63--68 MB; 0 drops/replays | R47 | VERIFIED, CAVEATED |
| RTT 0.052 ms average, 100 pings | R49 | VERIFIED, CAVEATED (short run) |
| GSO leak: ~7.4 GB SUnreclaim and panic before fix; flat after `consume_skb(seg)` | R47; D2.7 | VERIFIED |
| 64-packet replay window: 229 false drops, 107 retransmits; 1024: zero | R46; D2.8 | VERIFIED |
| Reassembled fragmented skb failed AEAD before `skb_linearize()` | D2.5; R34 | VERIFIED |
| Outer IPv4 ID was zero before fix | D2.6 | VERIFIED |
| Build clean with `make W=1` on 6.8.0-147 and 6.17.0-42; native 6.18.54.1 | R57; `native-w1.log` | VERIFIED |
| TC object/loader build with `-Wall -Wextra` clean | R57 | VERIFIED |

## Claims deliberately removed from the paper

| Draft claim | Why it is not in the paper |
|---|---|
| Single-byte XOR payload obfuscation | The current v4 datapath is AEAD; XOR provided no confidentiality or integrity. The paper says this explicitly. |
| Dynamic automatic key rotation every 300 s | Not implemented. Current rekey is manual, with dual-key grace and explicit commit. |
| `/proc/xorkey` interface | Removed. The current control plane is `/proc/torshield/{psk,peers,mode,stats}`. |
| +1% CPU usage | Not measured; no defensible CPU accounting exists in the captured runs. |
| 0.5 ms additional processing time per packet | Not measured. The paper reports throughput and a short RTT run instead. |
| 50 KB kernel footprint | Not measured for the current module; the old figure is not reused. |
| 5% throughput loss at 1 Gbit/s | Not measured; the current native numbers are absolute throughput, not a 5% delta. |
| 72-hour stability | Not tested. The longest controlled run is 30 s. |
| Ubuntu 20.04, CentOS 8, Debian 11 / kernels 5.4, 5.10, 5.15 | Not tested in this work. The build matrix is 6.8.0-147, 6.17.0-42, and native 6.18.54.1. |
| "Defeats statistical analysis" | False for a length-preserving transform and not claimed for the padded AEAD tunnel. |

## Known gaps that would strengthen a camera-ready submission

1. **Bare-metal throughput.** Current numbers are WSL2/Hyper-V, not bare metal.
2. **Real NIC/offload behavior.** veth only; checksum/offload on a physical NIC is untested.
3. **IPv6 TC deletion test.** The v6 guard hooks build, but the deletion suite is IPv4.
4. **TCX runtime test.** The TCX branch is compile-tested only.
5. **IPv6 rekey test.** Rekey is IPv4-only in the current evidence.
6. **Zero-race TC guard.** The residual check-to-egress race is documented, not closed.
7. **CPU cost model.** No per-packet CPU time or cycles/byte measurement.
8. **Venue metadata.** Target IEEE venue, page limit, authorship order, and submission deadline still need confirmation.
