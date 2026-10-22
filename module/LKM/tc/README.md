# TC clsact/eBPF egress classifier

The `tc` datapath steers inner traffic into a `torshield` netdevice with a
clsact/eBPF classifier instead of routes or netfilter:

- `torshield_tc.c` — `sched_cls` program that matches the **inner destination**
  against LPM tries of the configured peer prefixes and `bpf_redirect`s a match
  to the device. Outer frames carry `TS_TC_MARK` so they are not redirected
  again; multicast/link-local destinations and link-local sources are skipped.
- `torshield_tc_load.c` — `torshield-tc`, a libbpf loader that fills the maps,
  attaches to the underlay's clsact egress, and drives `/proc/torshield/mode`.
- `Makefile` — builds both.

The AEAD is **not** in BPF: it stays in `ndo_start_xmit`, because the helper set
cannot call the synchronous ChaCha20/Poly1305 path.

## Build

```bash
sudo apt-get install -y clang libbpf-dev libelf-dev zlib1g-dev
make                       # torshield_tc.o + torshield-tc
```

## Usage

```bash
# attach in the namespace that owns the underlay; prefixes come from
# /proc/torshield/peers. -4/-6 are optional extra prefixes.
sudo torshield-tc attach -o torshield_tc.o -i eth0 -d torshield0
sudo torshield-tc detach -i eth0

# optional fail-safe watchdog: revert to tunnel if the classifier disappears
sudo torshield-tc watch -i eth0 -n 1000
```

Options: `-i` underlay interface, `-d` torshield device, `-o` BPF object
(default `torshield_tc.o`), `-4`/`-6` extra inner prefixes (repeatable), `-m`
mode file (default `/proc/torshield/mode`). `watch` also takes `-n` (poll
interval in ms) and `-x` (exit after the first revert, useful with
`Restart=on-failure`).

`attach` reads every `allowed=` prefix from `/proc/torshield/peers`, fills the
LPM maps, and switches the mode to `tc` **only after** the program is attached;
`detach` switches back to `tunnel` before removing the qdisc. The redirect
ifindex lives in the classifier's own `cfg` map, so **each namespace needs its
own attach**. If a peer is added/deleted/cleared while mode is `tc`, the kernel
forces `tunnel`; rerun `attach` to rebuild the maps. This keeps a stale map from
silently omitting a peer prefix.

## Fail-closed kernel guard

Netfilter `POST_ROUTING` runs before TC egress, so `tc` mode bypasses the
netfilter encap. Relying on the classifier alone would be fail-open if the
qdisc or program disappeared. The module therefore registers IPv4/IPv6
`NF_INET_LOCAL_OUT` and `NF_INET_FORWARD` hooks, both before `POST_ROUTING`.
For a peer-destined packet they allow transmission only if the route output
device is a `torshield` device or still has a live egress classifier:

* a TCX `ts_tc_egress` program in `dev->tcx_egress`, or
* a live `cls_bpf` filter in the clsact mini-Qdisc (the current loader style).

Otherwise the packet is dropped (`NF_DROP`) and `tc_guard` in
`/proc/torshield/stats` increases. The classifier itself also returns
`TC_ACT_SHOT` when it matches a peer but `cfg[0]` has no redirect ifindex,
instead of returning `TC_ACT_OK`.

The guard proves only that a classifier is attached. `attach` closes the
map-completeness gap by reading `/proc/torshield/peers`; a peer-list change
forces `tunnel` until the loader reruns. Direct BPF map edits or a hand-loaded
classifier are outside the guarantee.

`torshield-tc watch` is now a recovery aid: while the mode is `tc` it polls the
underlay's egress filter and writes `tunnel` as soon as the `ts_tc_egress`
program is gone. It is not the security boundary.

**Residual race.** The guard's check and the later TC egress lookup are separate.
If the classifier is deleted after the guard accepts a packet but before that
packet reaches egress, the in-flight packet can still leave in clear. Deletion
tests prove fail-closed behaviour for subsequent packets, not a zero-race
guarantee. A last-chance `ndo_start_xmit` guard or a single steering point would
be required to close it; neither is implemented.

Example unit:

```ini
[Unit]
Description=TorShield TC fail-safe watchdog
After=network.target

[Service]
ExecStart=/usr/local/sbin/torshield-tc watch -i eth0 -n 1000
Restart=always

[Install]
WantedBy=multi-user.target
```

Verified deletion results on native 6.18.54.1 (`stage24.sh`/`stage25.sh`):
deleting the classifier or clsact qdisc while mode is `tc` produced **0 sent /
8 blocked (`EPERM`)** on a local socket, peer server **0**, `tc_guard +8`,
`dev_out +0`, `tun_out +0`; restoring the classifier gave echo **16/16**. On the
`FORWARD` path, classifier absent/deleted gave n3 outer **0**, `tc_guard +8`,
`dev_out +0`; classifier present gave `dev_out +8`, `tun_rx +8`, `tc_guard +0`.
The loader was attached with **no `-4/-6`** and read **2 IPv4 + 2 IPv6**
prefixes from `/proc/torshield/peers` (stage24); adding, deleting or clearing a
peer while mode `tc` forced `tunnel` (stage24). See
[`../../../TUN-HYBRID.md`](../../../TUN-HYBRID.md) §5 for the full table and the
bring-up defect note.
