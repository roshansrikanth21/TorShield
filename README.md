# TorShield

TorShield is a Linux kernel module that builds an **authenticated, encrypted
point-to-point tunnel** between hosts, transparently to applications and to the
routing stack. It replaces the original single-byte-XOR "obfuscation" module
with a real AEAD datapath.

The canonical implementation is [`module/LKM/torshield.c`](module/LKM/torshield.c).
It builds on Linux 6.8 (Ubuntu 24.04 LTS) and 6.17, and is clean under `make W=1`.

## Modes

| Mode | Default | Datapath |
|---|---|---|
| **Tunnel** | yes | Netfilter hooks (`POST_ROUTING` → encapsulate, `LOCAL_IN` after IP reassembly → decapsulate) for traffic whose destination is a configured peer |
| **Hybrid** | no | A TUN-style L3 netdevice (`torshield0`, rtnetlink kind `torshield`) whose `ndo_start_xmit` encapsulates traffic routed into it; the netfilter path stays active for everything else |
| **TC** | no | A clsact/eBPF classifier on the underlay redirects packets whose inner destination matches a peer prefix to the same `torshield` device; a kernel guard at `LOCAL_OUT`/`FORWARD` drops peer packets when that classifier is missing |
| Stream | no | Legacy length-preserving payload transform, kept for measurement/comparison only; **no authentication** |

Tunnel, hybrid and TC share one wire format and interoperate.

## What it does and does not provide

**Provides**

- ChaCha20-Poly1305 (RFC 7539) confidentiality **and** integrity per packet.
- Padding to 64-byte buckets, so ciphertext length leaks less than plaintext length.
- A 64-bit per-peer sequence number, used as the AEAD nonce and checked against a
  **1024-packet** replay window **after** authentication.
- **Manual key rotation** for per-peer keys: the old key stays accepted during a
  grace period, then an explicit commit removes it. This is not a handshake.
- Fail-closed behaviour in tunnel and hybrid modes: malformed, unauthenticated,
  replayed or unknown-source packets are dropped and counted, never forwarded.
- A kernel-side fail-closed guard in TC mode: peer-destined packets are dropped
  at `LOCAL_OUT`/`FORWARD` (before `POST_ROUTING`) unless the output device still
  has a live TC egress classifier. Classifier and qdisc deletion are tested; the
  narrow in-flight race is documented below.
- IPv4 and IPv6, TCP and UDP, inside one namespace or across namespaces.

**Does not provide**

- No handshake and no forward secrecy. Key rotation is **manual** and applies
  only to peers that already have a per-peer key; a legacy global-PSK peer must
  be reconfigured first.
- No metadata protection: outer addresses, ports, timing and approximate size remain visible.
- No PMTU discovery/ICMP relay. TCP MSS is clamped (1360 v4 / 1340 v6); large UDP
  datagrams rely on outer IP fragmentation and reassembly.
- No per-namespace configuration: the key, peer list and mode are global.
- TC's guard and the TC egress hook are separate reads. A classifier deletion
  that lands after the guard has accepted a packet but before egress can still
  release that one in-flight packet in clear; the tested removal cases are
  fail-closed for all subsequent packets. See the TC section.
- Limited DoS resistance only: an optional per-source fixed-window limiter
  (`ts_rl_pps`, off by default) can reject packets before `skb_linearize`/Poly1305;
  there is no cookie challenge.

For real-world privacy use WireGuard or IPsec. This is a research/teaching
implementation and a measurement vehicle.

## Wire format

```
outer IP | UDP:4789 | 16-byte header | padded ciphertext | 16-byte tag

header : 'T' 'S' | version 1 | flags (bit 0 = inner packet is IPv6) | 4 reserved | 64-bit BE seq
nonce  : 4-byte XOR fold of (src, dst) || 8-byte BE seq
AAD    : the 16-byte header
cipher : ChaCha20-Poly1305, plaintext zero-padded to a 64-byte bucket
```

The outer IPv4 ID is assigned per packet, so fragmented outer datagrams cannot be
misassociated on receive. UDP port 4789 is the default; it can be changed with the
`ts_port` module parameter (set it identically on both ends).

## Build and install

```bash
cd module/LKM
make                       # torshield.ko + torshieldctl
sudo install -D -m 0644 torshield.ko /lib/modules/$(uname -r)/extra/torshield.ko
sudo depmod -a
sudo modprobe torshield
```

For the TC path, build the classifier and its loader (needs `clang`, `libbpf-dev`):

```bash
cd module/LKM/tc
make                       # torshield_tc.o + torshield-tc
```

`chacha_x86_64` is a soft dependency and is loaded automatically.

## Configure

Run on **both** hosts with the same key, and list the other host as a peer:

```bash
sudo ./torshieldctl set-key 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
sudo ./torshieldctl add-peer 10.0.0.2
sudo ./torshieldctl list-peers
sudo ./torshieldctl status          # set / unset
```

The module is inert until a key **and** at least one peer are configured.
`/proc/torshield/{psk,peers,mode,stats}` are the raw interfaces (`0600`, except
read-only `stats` at `0444`); `torshieldctl` is a thin wrapper.

### Tunnel mode (default)

With host A at `10.0.0.1` and host B at `10.0.0.2`, configure each host with the
other's address as the peer. Any packet A sends to `10.0.0.2` is encapsulated to
`10.0.0.2:4789`; B authenticates, decrypts and re-injects it. B's replies are
encapsulated symmetrically.

In the test VM, peers are configured with the two namespace addresses
(`10.0.0.1`, `10.0.0.2`) and only traffic between those addresses is tunneled.

### Hybrid mode (route-based)

```bash
echo hybrid | sudo tee /proc/torshield/mode

# create a device bound to the underlay interface (selects the outer route)
sudo ip link add name torshield0 link eth0 type torshield
sudo ip link set torshield0 up
sudo ip route add 10.0.0.2/32 dev torshield0
```

In hybrid mode, packets routed into a `torshield` device are skipped by the
netfilter egress hook and encapsulated by `ndo_start_xmit`; all other peer traffic
still uses the transparent path. A hybrid peer and a plain tunnel peer interoperate.

Peers now support **cryptokey routing**: a per-peer key, allowed inner prefixes and
an outer endpoint, with endpoint roaming after authenticated traffic. The device
path can therefore carry inner prefixes that are distinct from the underlay; see
[`TUN-HYBRID.md`](TUN-HYBRID.md) §2.4.

### Manual rekey (per-peer keys)

```bash
sudo ./torshieldctl rekey-peer 10.0.0.2 <new-64-hex>   # keep old key accepted
sudo ./torshieldctl rekey-commit 10.0.0.2             # reject the old key now
sudo ./torshieldctl list-peers                        # shows prev=<key-id> during grace
```

`rekey-peer` moves the current key to the previous slot and starts sending with
the new key. The receiver accepts **both** key IDs until `rekey-commit`, which
erases the previous key. A second `rekey-peer` before `commit` is rejected, so
the oldest key cannot be silently discarded. This covers packets already in
flight, but it is not a staged handshake: both ends must be rekeyed, so peer
traffic can drop between the two commands. Use the peer's current endpoint, as
roaming may have changed it. There is no forward secrecy, and compromising either
key during the grace period is enough. Only peers with a per-peer key can rotate.

### TC mode (clsact/eBPF)

TC mode keeps the device and wire format but replaces routes with an eBPF classifier
on the underlay's clsact egress:

```bash
# run in the namespace that owns the underlay; allowed prefixes are read from
# /proc/torshield/peers. -4/-6 are optional extra prefixes.
sudo torshield-tc attach -o torshield_tc.o -i eth0 -d torshield0
```

`torshield-tc attach` switches `/proc/torshield/mode` to `tc` **only after** the
program is attached; `torshield-tc detach -i eth0` switches back to `tunnel` before
removing the qdisc. Each namespace needs its own attach (the redirect ifindex is
per-namespace). The loader reads every `allowed=` prefix from
`/proc/torshield/peers`, so a missing `-4/-6` cannot silently leave a peer prefix
unredirected. If a peer is added, deleted or cleared while mode is `tc`, the
kernel forces mode back to `tunnel`; rerun `attach` to rebuild the maps and
re-enter `tc`. Direct edits to the BPF maps or a hand-loaded classifier are
outside this guarantee.

#### Fail-closed guard (tested)

`tc` mode no longer relies only on the userspace watchdog. The module registers
IPv4/IPv6 `NF_INET_LOCAL_OUT` and `NF_INET_FORWARD` hooks (both before
`POST_ROUTING`). For a peer-destined packet, the guard looks at the **route's
output device** (`nf_hook_state.out`):

* a `torshield` device is an encapsulating path and is allowed;
* otherwise the device must still have a live TC egress classifier. The guard
  recognises either a TCX `ts_tc_egress` program in `dev->tcx_egress`, or a
  live `cls_bpf` filter in the clsact mini-Qdisc (the attachment style used by
  `torshield-tc` today; the TCX branch is compile-tested, not runtime-tested);
* if neither is present, the packet is dropped and `tc_guard` in
  `/proc/torshield/stats` is incremented. A local `sendto()` then fails with
  `EPERM`; no clear frame reaches the underlay.

The classifier itself also drops (`TC_ACT_SHOT`) when it matches a peer but its
`cfg[0]` redirect target is missing, instead of falling through to `TC_ACT_OK`.
`torshield-tc watch` remains useful as a recovery aid: it reverts the mode to
`tunnel` after the classifier disappears. It is no longer the security boundary.

**Residual race.** The guard and the later TC egress hook are two separate reads
of `dev->tcx_egress`/the mini-Qdisc. If a classifier is deleted after the guard
has accepted a packet but before that packet reaches TC egress, the in-flight
packet can still leave in clear. The deletion tests below prove fail-closed
behaviour for all subsequent packets; they do not prove a zero-race guarantee.
A single steering point (or a last-chance xmit hook) would be required for that,
and is not implemented. The deletion tests are IPv4; the IPv6 guard hooks build
but the v6 removal path is not separately runtime-tested. Peer changes and
`attach` are not one atomic transaction: do not reconfigure peers concurrently
with `torshield-tc attach`. See [`TUN-HYBRID.md`](TUN-HYBRID.md) §5.

## Verified results

Environment for the correctness table: Ubuntu 24.04, kernel `6.8.0-147-generic`,
QEMU 8.2 with TCG (no KVM). Throughput was measured separately on the native
kernel, because TCG CPU emulation is not a throughput measurement.

### Native measurements (WSL2, kernel 6.18.54.1)

Native build: WSL2 `6.18.54.1-microsoft-standard-WSL2`, module built against the
full in-tree `Module.symvers` (vermagic match, `libchacha` auto-loaded). This is
a Hyper-V VM with 16 vCPUs, **not bare metal**; the direct-veth baseline shows
the link is not the bottleneck.

| Test | Result |
|---|---|
| Baseline, direct veth, 4-stream TCP, 3 runs | **100.98 / 99.76 / 97.84 Gbit/s** |
| Tunnel, 1-stream TCP, 3 runs | **909.7 / 921.5 / 965.4 Mbit/s**, 0 retransmits |
| Tunnel, 4-stream TCP, 3 runs | **3345.6 / 3018.1 / 3203.1 Mbit/s**, ≤3 retransmits |
| Tunnel, 30 s sustained 4-stream TCP | **3.40 Gbit/s**; `SUnreclaim` flat at **63–68 MB**; no panic; `tun_drop 0`, `tun_replay 0` |
| Tunnel RTT, 100 pings | **0.052 ms avg** (baseline 0.067 ms) |
| Tunnel v4/v6 UDP echo | **256/256** and **64/64** |
| Native stages 16/17/20 | v4/v6 **100%**; replay **1**, tamper drop **1**, ACL **1**, unknown peer **1** (exact) |
| Native TC, v4/v6 echo | **256/256**, **64/64**; `dev_out 647`, `tun_out 0`, `tun_drop 0`, `dev_drop 0`; detach fallback **16/16** |
| Native TC wire, v4 | **210/210** authenticated with `K`, **0/210** with the global PSK |

Two issues were exposed only by sustained native load and are fixed:

* **GSO skb leak.** The egress GSO loop copied each segment into the outer skb but
  never freed the original segment. A 30 s 4-stream run drove
  `slab_unreclaimable` to ~7.4 GB and panicked the VM. The missing
  `consume_skb(seg)` is added; the same 30 s run now holds `SUnreclaim` at
  63–68 MB and completes at 3.40 Gbit/s.
* **Replay window too narrow.** 4-stream traffic reordered beyond a 64-packet
  window, producing 229 false replay drops and TCP retransmits. The window is now
  **1024 packets**; the same 4-stream run records **0** replays and no retransmits.

| Test | Result |
|---|---|
| Tunnel, IPv4 TCP 1 MB | **1,048,576/1,048,576 bytes correct (100%)**; 1054 frames |
| Tunnel, IPv6 TCP 256 KB | **262,144/262,144 bytes correct (100%)** |
| Independent AEAD check of the on-wire capture | **1054/1054 frames authenticated** (Python `cryptography`); SYN MSS 1360 |
| Tunnel, 4000-byte UDP datagram | **4000/4000 correct (100%)**; outer split into 3 IP fragments |
| Tunnel, 60000-byte UDP datagram | **60000/60000 correct (100%)**; outer split into 41 IP fragments |
| Replay / tampered / unknown-source packet | all dropped; `tun_replay`, `tun_drop`, `tun_peer` counters exact |
| Packet built by an independent Python sender | accepted and delivered (format/nonce/AAD agree) |
| Hybrid, IPv4 TCP 1 MB via `ndo_start_xmit` | **100%**; 807/807 frames authenticated; inner MSS 1320; `dev_out 1021`, `dev_drop 0` |
| Hybrid, IPv6 TCP 256 KB via `ndo_start_xmit` | **100%**; 209/209 frames authenticated |
| Cryptokey routing, v4/v6 echo | **256/256** and **64/64**; per-peer key **246/246** authenticated, global PSK **0/246**; disallowed inner source dropped; endpoint roaming verified |
| TC, IPv4 UDP echo 256 KB | **256/256**; `dev_out 512`, `tun_out 0`, `tun_drop 0`, `dev_drop 0` |
| TC, IPv6 UDP echo 64 KB | **64/64**, retries 0; `dev_out 647`, `tun_out 0`, `tun_acl 0`, drops 0 |
| TC, independent AEAD on the wire | v4 **210/210** with `K`, **0/210** with the global PSK; v6 **68/68** with `K6`, **0/68** with the PSK |
| TC, detach fallback | mode returns to `tunnel`; netfilter echo **16/16**, `tun_out +32` |
| TC fail-closed, classifier deleted (`stage24`) | `sendto` **0 sent / 8 blocked (`EPERM`)**, peer server received **0**, `tc_guard +8`, `dev_out +0`, `tun_out +0` |
| TC fail-closed, clsact qdisc deleted (`stage24`) | same: **0 sent / 8 blocked**, server **0**, `tc_guard +8`, `dev_out +0`, `tun_out +0` |
| TC fail-closed, restore (`stage24`) | reattach classifier: echo **16/16**; detach: netfilter fallback **8/8** |
| TC peer-change invalidation (`stage24`) | `add-peer`, `del-peer` and `clear-peers` while mode=`tc` each changed the mode to **tunnel**; loader auto-fill (no `-4/-6`) reported **2 IPv4 + 2 IPv6** prefixes |
| TC FORWARD guard (`stage25`) | AF_PACKET injection on n1 bypasses its `LOCAL_OUT`. Classifier absent: n2 ingress **8**, n3 outer **0**, `tc_guard +8`, `dev_out +0`; classifier present: `tc_guard +0`, `dev_out +8`, n3 `tun_rx +8`; classifier deleted: n3 outer **0**, `tc_guard +8`, `dev_out +0` |
| Per-source rate limiter (`ts_rl_pps=50`) | **950/1000** stopped before the AEAD, **50** reached it; legitimate echo **64/64** |
| Manual rekey (native stage23) | captured **egress** key id changed K→K2 (`4290739141`→`1666914373`); old + new keys accepted during grace **4/4** payloads; post-commit old-key packet rejected as non-peer **1**, `tun_in +4`, `tun_peer +1`, `tun_replay 0` |
| TC watchdog | external `tc qdisc del` reverted mode to `tunnel` within **~0.5 s** (200 ms poll) |
| `make W=1` | clean on 6.8.0-147 and 6.17.0-42 |

Several real defects were found by these tests and fixed: the decap read only the
linear head of a reassembled (fragmented) skb, the outer IPv4 ID was always 0, and
the first TC v6 run redirected underlay NDP (shared inner/outer addresses) and
link-local-source solicitations, which the peer ACL rejected. They are documented
in [`TO-DO.md`](TO-DO.md) (D2.5, D2.6, and the TC bring-up note in
[`TUN-HYBRID.md`](TUN-HYBRID.md) §5).

**Withdrawn claims.** Earlier documents reported 1266 Mbps TCP (−47%) and called
the transform "obfuscation that defeats statistical analysis". Those numbers were
measured on a path that was not actually encrypting, and the claim is false for a
length-preserving transform. They are not results of this code.

## Reproducing the tests

The VM harness lives in [`.work/vm-src/`](.work/vm-src/):

| Script | Purpose |
|---|---|
| `stage16.sh` | tunnel acceptance: build/load, IPv4 1 MB, IPv6 256 KB, UDP, replay, tamper |
| `stage17.sh` | replay/tamper/unknown-peer accounting plus independent-sender interop |
| `stage18.sh` | hybrid device creation, IPv4/IPv6 through `ndo_start_xmit`, coexistence |
| `stage19.sh` | large UDP datagrams (4 KB, 60 KB) and outer fragmentation analysis |
| `stage20.sh` | cryptokey routing: per-peer keys, allowed prefixes, ACL, endpoint roaming |
| `stage21.sh` | TC attach/detach, IPv4/IPv6 echo, path counters, fallback to `tunnel` |
| `stage23.sh` | manual rekey: dual-key grace, explicit commit, old-key rejection |
| `stage24.sh` | TC fail-closed: delete classifier and qdisc at `LOCAL_OUT`, verify blocked sends and counters, restore |
| `stage25.sh` | TC fail-closed at `FORWARD`: raw AF_PACKET injection into a forwarding namespace; classifier absent/present/deleted |
| `runlegacy2.sh` | re-runs stages 16–20 on a clean module |
| `verify_tunnel.py` | host-side ChaCha20-Poly1305 verification of a capture |
| `defrag_verify.py` | defragments IPv4 captures, then verifies the AEAD |
| `inject.py` / `replay.py` | independent packet builder, replay/tamper harness |
| `inject2.py` / `sniff_key.py` | per-peer-key packet builder; captures the outer key id/seq for rekey evidence |

`stage*.sh` are run as root inside the VM; `verify_tunnel.py` and
`defrag_verify.py` run on the host against the captured pcap.

## Repository layout

```
module/LKM/            canonical kernel module + torshieldctl
module/LKM/tc/         clsact/eBPF classifier + torshield-tc loader
module/test/           legacy userspace self-test and testbed (stream mode)
.work/vm-src/          QEMU/netns test harness used for every result above
TUN-HYBRID.md          hybrid TUN and TC design, trade-offs, verified results
TO-DO.md               master tracker: decisions, defects, evidence log
CONTEXT.md             historical handoff narrative (partly superseded; see its banner)
original_repo/         the original XOR module, kept as the "before" artifact
TorShield_Module/      frozen v2 snapshot, kept for the paper; not the current code
```
