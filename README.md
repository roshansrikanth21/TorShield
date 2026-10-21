# TorShield tests

Two levels of testing: a userspace self-test that runs anywhere (no root),
and a full network-namespace testbed that loads the real module (root).

## 1. Userspace self-test (`ts_selftest.c`) — no root

Reimplements the module's transform (SipHash-2-4 keystream, payload XOR,
RFC 1071 checksum fix-up) in userspace and checks the properties the module
relies on. Build and run:

```bash
gcc -Wall -Wextra -O2 -fno-strict-aliasing -o ts_selftest ts_selftest.c
./ts_selftest
```

What it verifies:

- **Round-trip:** `decrypt(encrypt(p)) == p` for every length 0..2048.
- **Key sync:** same (PSK, window) → identical keystream; a different window
  or PSK → different keystream. This is what keeps two hosts in sync.
- **Checksum:** after encrypt + recompute, an independent RFC 1071 check of
  the TCP/UDP checksum passes; after decrypt the original checksum returns.

Result on the dev machine: **all correctness tests pass.**

### Measured obfuscation cost (microbenchmark, single core)

| Quantity | Value |
|---|---|
| Keystream XOR throughput | ~1.8 GB/s |
| Per-packet obfuscation (XOR + checksum, 1460 B) | **~1.2 µs** |
| Implied single-core ceiling @1460 B | ~10 Gbps |

These are userspace numbers with an unoptimized checksum; the kernel's
`csum_partial` is faster, so this is an upper bound on the per-packet cost.
Note this is **~1.2 µs per packet, not 0.5 ms** — the figure in the current
paper (Table I) is off by roughly 400× and should be replaced with a measured
value.

## 2. Network-namespace testbed (`run_testbed.sh`) — needs root

Loads the real `torshield.ko`, wires two namespaces (`10.0.0.1` ↔ `10.0.0.2`)
with a veth pair, and tests end-to-end behaviour and performance.

```bash
sudo bash run_testbed.sh
```

Prerequisites: a kernel that can load out-of-tree modules, matching headers
(`linux-headers-$(uname -r)`), and `gcc make iproute2 iperf3 tcpdump python3`.

> **WSL2:** the stock WSL kernel ships stub headers and cannot load this
> module. Run this on a normal Ubuntu/Debian host or VM, or a cloud instance.

What it proves/measures:

- **End-to-end:** a plaintext marker sent over TCP from ns1 arrives intact at
  ns2 (both ends decrypt correctly).
- **Obfuscation on the wire:** the same marker does **not** appear in cleartext
  in a `tcpdump` capture of the veth — the payload is obfuscated in flight.
- **Throughput & CPU:** iperf3 TCP and UDP, run **with** TorShield (peers set)
  and **without** (peers cleared → module inert). The with/without numbers are
  what Table I and Fig. 2 in the paper should report, replacing the current
  unverified values.

The script tears down the namespaces and unloads the module on exit.
