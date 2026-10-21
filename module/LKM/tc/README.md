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
# attach in the namespace that owns the underlay; repeat -4/-6 per prefix
sudo torshield-tc attach -o torshield_tc.o -i eth0 -d torshield0 \
    -4 10.0.0.1/32 -4 10.0.0.2/32 \
    -6 fd00::1/128 -6 fd00::2/128
sudo torshield-tc detach -i eth0
```

Options: `-i` underlay interface, `-d` torshield device, `-o` BPF object
(default `torshield_tc.o`), `-4`/`-6` inner prefixes (repeatable), `-m` mode file
(default `/proc/torshield/mode`).

`attach` switches the mode to `tc` **only after** the program is attached;
`detach` switches back to `tunnel` before removing the qdisc. The redirect
ifindex lives in the classifier's own `cfg` map, so **each namespace needs its
own attach**.

## Fail-open caveat

Netfilter `POST_ROUTING` runs before TC egress, so `tc` mode bypasses the
netfilter encap and depends entirely on the classifier. If the qdisc or program
disappears while the mode is `tc` (for example `tc qdisc del`, a module reload,
or attaching in the wrong namespace), peer traffic leaves **in the clear**. A
supervisor is required; `tc` mode is not fail-closed. The `attach`/`detach`
ordering above only covers the normal path.

Verified results and the bring-up defect note: [`../../../TUN-HYBRID.md`](../../../TUN-HYBRID.md) §5.
