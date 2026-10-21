#!/bin/bash
#
# TorShield network-namespace testbed.
#
#   Builds the module, wires two network namespaces with a veth pair, loads
#   TorShield on the host (hooks run in every namespace), and then:
#     * proves TCP and UDP traffic survives end-to-end with obfuscation on,
#     * proves the bytes on the wire are obfuscated (a plaintext marker does
#       not appear in a capture, but the receiver still gets it),
#     * measures throughput (iperf3 TCP + UDP) and CPU with vs. without.
#
#   REQUIRES ROOT.  Run:   sudo bash run_testbed.sh
#
#   Prerequisites: a kernel that can load out-of-tree modules, matching
#   headers (linux-headers-$(uname -r)), and: gcc make iproute2 iperf3 tcpdump
#
#   NOTE on WSL2: the stock WSL kernel ships stub headers and cannot load
#   this module. Use a normal Ubuntu/Debian host or VM, or a cloud instance.
#
set -u

LKM_DIR="${LKM_DIR:-$(cd "$(dirname "$0")/../LKM" && pwd)}"
NS1=ts-ns1
NS2=ts-ns2
IP1=10.0.0.1
IP2=10.0.0.2
PSK=00112233445566778899aabbccddeeff
MARKER=TORSHIELD_PLAINTEXT_MARKER_42
FAIL=0

say()  { printf '\n=== %s ===\n' "$*"; }
ok()   { printf '  [PASS] %s\n' "$*"; }
bad()  { printf '  [FAIL] %s\n' "$*"; FAIL=1; }

[ "$(id -u)" = 0 ] || { echo "Must run as root (sudo bash $0)"; exit 1; }

# ---- prerequisites ------------------------------------------------------
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1"; MISS=1; }; }
MISS=0; for c in gcc make ip iperf3 tcpdump; do need "$c"; done
[ "$MISS" = 1 ] && { echo "Install the missing tools and re-run."; exit 1; }

# ---- build --------------------------------------------------------------
say "Building module"
KDIR="/lib/modules/$(uname -r)/build"
if [ ! -e "$KDIR/Makefile" ]; then
	echo "No kernel build tree at $KDIR."
	echo "Install: sudo apt-get install -y linux-headers-\$(uname -r)"
	exit 1
fi
make -C "$LKM_DIR" >/dev/null || { echo "build failed"; exit 1; }
KO="$LKM_DIR/torshield.ko"
CTL="$LKM_DIR/torshieldctl"
[ -f "$KO" ] && ok "built torshield.ko" || { bad "no .ko"; exit 1; }

cleanup() {
	ip netns del $NS1 2>/dev/null
	ip netns del $NS2 2>/dev/null
	rmmod torshield 2>/dev/null
}
trap cleanup EXIT

# ---- topology -----------------------------------------------------------
say "Setting up namespaces $NS1 <-> $NS2"
cleanup
ip netns add $NS1
ip netns add $NS2
ip link add veth1 netns $NS1 type veth peer name veth2 netns $NS2
ip -n $NS1 addr add $IP1/24 dev veth1
ip -n $NS2 addr add $IP2/24 dev veth2
ip -n $NS1 link set veth1 up
ip -n $NS2 link set veth2 up
ip -n $NS1 link set lo up
ip -n $NS2 link set lo up
# large MTU-safe defaults; disable checksum offload so the SW path is exercised
ip netns exec $NS1 ethtool -K veth1 tx off rx off 2>/dev/null
ip netns exec $NS2 ethtool -K veth2 tx off rx off 2>/dev/null
ok "veth pair up ($IP1, $IP2)"

# ---- load + configure ---------------------------------------------------
say "Loading and configuring TorShield"
insmod "$KO" || { bad "insmod failed"; exit 1; }
"$CTL" set-key $PSK
"$CTL" add-peer $IP1          # config is global; both ends must be peers
"$CTL" add-peer $IP2
"$CTL" window 300
"$CTL" status
"$CTL" list-peers
ok "module loaded, PSK set, peers = $IP1 $IP2"

# ---- correctness: link up (ICMP is not obfuscated) ----------------------
say "Correctness"
if ip netns exec $NS1 ping -c1 -W2 $IP2 >/dev/null 2>&1; then
	ok "ICMP reaches peer (link works)"
else
	bad "ping failed"
fi

# ---- correctness: TCP end-to-end + wire is obfuscated -------------------
# Receiver in NS2 listens; capture on NS2's veth; sender in NS1 sends marker.
# Uses python3 for a portable TCP server/client (no nc-flavour issues).
CAP=$(mktemp)
RX=$(mktemp)
ip netns exec $NS2 timeout 8 tcpdump -i veth2 -w "$CAP" -U tcp 2>/dev/null &
TPID=$!
sleep 1
ip netns exec $NS2 timeout 6 python3 - "$RX" <<'PY' &
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 9000)); s.listen(1); s.settimeout(5)
c, _ = s.accept()
data = c.recv(4096)
open(sys.argv[1], "wb").write(data)
PY
sleep 1
ip netns exec $NS1 timeout 3 python3 - "$IP2" "$MARKER" <<'PY'
import socket, sys, time
c = socket.socket(); c.connect((sys.argv[1], 9000))
c.sendall(sys.argv[2].encode()); time.sleep(0.3); c.close()
PY
sleep 2
kill $TPID 2>/dev/null; wait $TPID 2>/dev/null

if grep -qa "$MARKER" "$RX"; then
	ok "TCP payload delivered intact (receiver saw marker)"
else
	bad "receiver did NOT get the marker (decryption/path broken)"
fi
if tcpdump -r "$CAP" -A 2>/dev/null | grep -qa "$MARKER"; then
	bad "marker visible in cleartext on the wire (NOT obfuscated)"
else
	ok "marker NOT in cleartext on the wire (payload obfuscated)"
fi
rm -f "$CAP" "$RX"

# ---- performance: with vs without --------------------------------------
parse_tcp() { python3 -c 'import sys,json;d=json.load(sys.stdin);print("%.0f Mbps (sender CPU %.1f%%)"%(d["end"]["sum_received"]["bits_per_second"]/1e6,d["end"]["cpu_utilization_percent"]["host_total"]))' 2>/dev/null || echo "n/a"; }
parse_udp() { python3 -c 'import sys,json;d=json.load(sys.stdin);e=d["end"]["sum"];print("%.0f Mbps, loss %.2f%%"%(e["bits_per_second"]/1e6,e["lost_percent"]))' 2>/dev/null || echo "n/a"; }

perf_run() {   # $1 = label
	ip netns exec $NS2 iperf3 -s -1 -D --logfile /dev/null 2>/dev/null
	sleep 1
	printf '  %-8s TCP: ' "$1"
	ip netns exec $NS1 iperf3 -c $IP2 -t 5 -J 2>/dev/null | parse_tcp
	ip netns exec $NS2 iperf3 -s -1 -D --logfile /dev/null 2>/dev/null
	sleep 1
	printf '  %-8s UDP: ' "$1"
	ip netns exec $NS1 iperf3 -c $IP2 -u -b 0 -t 5 -J 2>/dev/null | parse_udp
}

say "Performance WITH TorShield (peers set)"
perf_run "with"

say "Performance WITHOUT TorShield (peers cleared -> inert)"
"$CTL" clear-peers
perf_run "without"

say "Summary"
[ "$FAIL" = 0 ] && echo "  ALL CORRECTNESS CHECKS PASSED" || echo "  SOME CHECKS FAILED"
echo "  (throughput numbers above are the with/without comparison for Table I / Fig. 2)"
exit $FAIL
