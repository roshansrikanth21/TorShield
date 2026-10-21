# TorShield tests

Two levels of testing: a userspace self-test that runs anywhere (no root),
and a full network-namespace testbed that loads the real module (root).

## 1. Userspace self-test (`ts_selftest.c`) — no root

Reimplements the module's cipher (ChaCha20, RFC 8439) and the RFC 1071
checksum fix-up in userspace and checks the properties the module relies on.
On a little-endian host this ChaCha20 matches the kernel's byte-for-byte.
Build and run:

```bash
gcc -Wall -Wextra -O2 -fno-strict-aliasing -o ts_selftest ts_selftest.c
./ts_selftest
```

What it verifies:

- **Round-trip:** `decrypt(encrypt(p)) == p` for every length 0..2048.
- **Keystream = f(key, nonce):** same (key, nonce) → identical keystream, so
  two hosts agree; a different nonce or key → a different stream.
- **Checksum:** after encrypt + recompute, an independent RFC 1071 check of
  the TCP/UDP checksum passes; after decrypt the original checksum returns.

Result on the dev machine: **all correctness tests pass.**

### Note on the microbenchmark

The self-test also prints a ChaCha20 throughput number, but it uses a plain
scalar reference implementation (~160 MB/s), which is **not** representative:
the kernel module uses the SIMD-accelerated `lib/crypto` ChaCha20, which runs
several times faster. The per-packet cost that matters for the paper comes
from the real kernel run in the testbed below, not from this reference.

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
