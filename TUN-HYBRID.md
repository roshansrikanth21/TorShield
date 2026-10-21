# Hybrid networking: a TUN-style netdevice for tunnel mode (option B)

**Status:** prototype implemented and runtime-verified on 6.8.0-147 (QEMU).
**Build:** clean on 6.8.0-147 and 6.17.0-42.
**Code:** `module/LKM/torshield.c` — `ts_ndo_start_xmit`, `ts_dev_setup`,
`ts_newlink`, `ts_link_ops`, `TS_MODE_HYBRID`.
**Test:** `.work/vm-src/stage18.sh`.

---

## 1. What "hybrid" means here

Option B (the UDP tunnel) has two separable parts:

1. **What gets encapsulated** — currently decided by a netfilter hook that matches the
   *destination address* against a peer list (`NF_INET_POST_ROUTING`).
2. **How it is encapsulated** — UDP:4789 + 16-byte header + ChaCha20-Poly1305 +
   64-byte padding buckets + 16-byte tag.

"Hybrid" keeps (2) byte-for-byte and adds a second way to select traffic for (1): a
**kernel L3 netdevice** (`torshield0`, rtnetlink kind `torshield`) whose `ndo_start_xmit`
encapsulates whatever routing sends to it. That is the in-kernel equivalent of the TUN
protocol: a virtual interface that carries IP packets, with no Ethernet header and no ARP.

Two architectures were considered:

| | Kernel netdevice (chosen) | `tun(4)` + userspace daemon |
|---|---|---|
| Data path | in-kernel, one copy | kernel ↔ userspace ↔ kernel (2 copies + syscalls) |
| Crypto | existing in-kernel AEAD | daemon (or a second kernel path) |
| Deployment | `ip link add` / `ip route` | daemon + `/dev/net/tun` + config protocol |
| Failure mode | routing only | daemon crash breaks the tunnel |
| Code reuse | full (same encap functions) | framing must be reimplemented or exported |

The netdevice wins on reuse and on having no userspace dependency. It is also the only
option that lets both datapaths coexist in one namespace without a mode switch per packet.

---

## 2. Design

### 2.1 Device

```
ip link add name torshield0 link veth1 type torshield
ip link set torshield0 up
ip route add 10.0.0.2/32 dev torshield0
```

* `rtnl_link_ops.kind = "torshield"`, so the device can be created in **any** netns.
* `IFLA_LINK` (the generic `link DEV` argument) selects the **underlay** interface. It is
  stored in `netdev_priv()` as `priv->link`.
* `ARPHRD_NONE`, `hard_header_len = 0`, `addr_len = 0`, `IFF_POINTOPOINT | IFF_NOARP`,
  `IFF_NO_QUEUE`: no L2, no neighbour resolution, no qdisc.
* MTU 1360, `min_mtu 576`, `max_mtu 1360`. The worst case is
  1360 + 63 (padding) + 60 (outer IP/UDP/header/tag) = 1483 < 1500, so the outer packet is
  never fragmented. TCP derives MSS 1320 (v4) from the route MTU — no MSS-clamp hack is
  needed on this path (verified: inner SYN MSS **1320**).

### 2.2 Egress (`ndo_start_xmit`)

```
skb (L3, no Ethernet header)
  │  version 4 or 6
  ├─ destination multicast / link-local / loopback?  → consume (never tunnelable)
  ├─ peer lookup by inner destination                → no peer: drop (+ counter)
  ├─ per-peer 64-bit sequence (same counter as the netfilter path)
  ├─ outer route lookup pinned to priv->link         → recursion guard (dst->dev == dev?)
  └─ ts_tun_encap_v4() / ts_tun_encap_v6()           → UDP:4789 AEAD, ip_local_out()
```

The **underlay-pinned route lookup** is the important part. With route-based steering there
is normally a route such as `10.0.0.2/32 dev torshield0`; an unqualified lookup of the outer
destination would match that same route and recurse forever. Setting `flowi4_oif` /
`flowi6_oif` to the underlay ifindex forces the lookup through `veth1`. A `dst->dev == dev`
check remains as a second line of defence.

If the peer or the underlay is missing the packet is dropped (fail-closed), counted in
`dev_drop`, and the reason is logged rate-limited (`reason=1..6`).

### 2.3 Coexistence (`TS_MODE_HYBRID`)

`/proc/torshield/mode` accepts `hybrid` in addition to `tunnel` and `stream`.

In hybrid mode the netfilter egress hook still runs, but **skips any packet whose route
points at a `torshield` netdevice** (`skb_dst(skb)->dev->rtnl_link_ops == &ts_link_ops`).
Those packets are encapsulated later by `ndo_start_xmit`; everything else keeps the
transparent path. Consequently:

* one namespace can have routed traffic through `torshield0` **and** transparent
  peer-to-peer traffic at the same time;
* a hybrid peer interoperates with a plain tunnel peer, because the wire format is identical;
* the mode is global, so no per-netns mode state is required.

Ingress is unchanged in both modes: the UDP decap at `NF_INET_LOCAL_IN` authenticates,
checks the replay window, decrypts and re-injects the inner packet.

### 2.4 Address model (prototype limitation)

The prototype uses **inner == outer** addresses: the outer header copies the inner source
and destination, exactly like the netfilter path. That is sufficient to prove the datapath,
but a general route-based deployment needs:

* a distinct **tunnel address** per endpoint (the outer address),
* a **peer endpoint mapping** (inner prefix → outer endpoint), and
* policy routing so that the inner prefix is routed into `torshield0` while the underlay
  prefix stays on the physical link.

Those are configuration-plane changes; the wire format already carries everything needed
(family bit + 64-bit sequence + AEAD over the header).

---

## 3. Verified results (stage18.sh, kernel 6.8.0-147)

Topology: netns n1 (`10.0.0.1`, `fd00::1`) ↔ netns n2 (`10.0.0.2`, `fd00::2`) over
`veth1`/`veth2`. n1 has `torshield0` with `link veth1`; mode is `hybrid` on both sides
(the module is global). n2 has no `torshield` device, so its replies use the netfilter path.

| Check | Result |
|---|---|
| Device creation `ip link add … link veth1 type torshield` | `rc=0`, MTU 1360, `qdisc noqueue`, `link/none` |
| Small TCP marker bound to `10.0.0.1` | `HYBRID_OK` received |
| **TCP 1 MB through `ndo_start_xmit`** | **1048576/1048576 correct (100%)** |
| **IPv6 TCP 256 KB through `ndo_start_xmit`** | **262144/262144 correct (100%)** |
| Packets sent by the device | `dev_out 1020`, `dev_drop 0`, TX 1 367 953 bytes |
| Outer frames at n2, v4 capture | 807 frames, 807 valid headers, 0 bad padding, 0 plaintext bytes |
| Outer frames at n2, v6 capture | 208 frames, 208 valid headers, 0 bad padding, 0 plaintext bytes |
| Independent AEAD check (python-`cryptography`) | **807/807** v4 and **208/208** v6 authenticated |
| Inner SYN MSS on the device path | **1320** (route MTU 1360 − 40) |
| Netfilter path still active at the same time | `tun_out 173` (n2's replies encapsulated transparently) |

Observed during bring-up: the kernel emits IPv6 router solicitations on a new interface.
They are link-scoped (`ff02::2`) and are now consumed by the multicast/link-local guard
instead of being counted as malformed drops (`dev_drop` went from 3–5 per run to 0).

---

## 4. Trade-offs and limits

* **No GSO on the device.** The device advertises no offloads, so the stack segments to the
  route MTU before `ndo_start_xmit`. This is simple and correct but gives up GSO batching;
  the netfilter path still uses GSO. Adding `NETIF_F_GSO` would require segmenting inside
  the driver.
* **Same-address model** (see 2.4). Not yet suitable for overlapping inner prefixes.
* **One underlay per device.** Multipath/ECMP and endpoint roaming are not implemented.
* **No PMTU discovery / ICMP relay.** The MTU is static at 1360 and TCP adapts via MSS.
* **Peer list and key are global** (shared by all netns), as in tunnel mode.
* **No rekeying, no handshake, no DoS cookie** — unchanged from tunnel mode.
* **Global mode switch.** `hybrid` affects every namespace; per-netns modes would need
  per-netns state.

---

## 5. Next steps

1. Split inner/outer addressing: endpoint mapping plus policy routing, so `torshield0` can
   carry prefixes that overlap the underlay.
2. Advertise GSO/TSO and segment in the driver, then re-measure throughput.
3. Deliver decapped packets through the tunnel netdevice (`skb->dev = torshield0`) so that
   `rp_filter`, policy routing and per-device counters apply to ingress as well.
4. Add a small control plane (`ip link set … type torshield peer …`) instead of relying on
   the global peer list.
5. Re-run the measurement suite on real hardware; the current numbers are TCG-emulated.
