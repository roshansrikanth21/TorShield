#!/bin/bash
# Boot the Ubuntu cloud image under QEMU (TCG, no KVM) with NoCloud user-data
# served over HTTP from the host, and wait until SSH is up on localhost:2222.
set -u
Q=$HOME/qemu
export LD_LIBRARY_PATH="$Q/root/usr/lib/x86_64-linux-gnu:$Q/root/lib/x86_64-linux-gnu:$Q/root/usr/lib"
QE="$Q/root/usr/bin/qemu-system-x86_64"
IMG=$HOME/vm/noble.img
SEED=$HOME/vm/seed
mkdir -p "$SEED"

# Fresh overlay each boot so the base image stays pristine.
[ -f "$HOME/vm/disk.qcow2" ] || "$Q/root/usr/bin/qemu-img" create -f qcow2 -F qcow2 -b "$IMG" "$HOME/vm/disk.qcow2" 40G

PUB=$(cat "$HOME/.ssh/id_ed25519.pub" 2>/dev/null || cat /mnt/c/Users/rosha/.ssh/id_ed25519.pub)
cat > "$SEED/user-data" <<EOF
#cloud-config
users:
  - name: ts
    plain_text_passwd: torshield
    lock_passwd: false
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $PUB
ssh_pwauth: true
package_update: false
EOF
cat > "$SEED/meta-data" <<EOF
instance-id: torshield-vm
local-hostname: torshield-vm
EOF

# Serve the seed (idempotent).
if ! ss -ltn 2>/dev/null | grep -q ':8000 '; then
  ( cd "$SEED" && nohup python3 -m http.server 8000 --bind 0.0.0.0 >"$HOME/vm/http.log" 2>&1 & )
  sleep 1
fi

# Kill any old VM.
pkill -f 'qemu-system-x86_64.*disk.qcow2' 2>/dev/null
sleep 1

nohup "$QE" \
  -machine pc -accel tcg -cpu max -smp 2 -m 2048 \
  -drive file="$HOME/vm/disk.qcow2",if=virtio,cache=writeback \
  -netdev user,id=n0,hostfwd=tcp::2222-:22 -device virtio-net-pci,netdev=n0 \
  -smbios type=1,serial='ds=nocloud-net;s=http://10.0.2.2:8000/' \
  -display none -serial file:"$HOME/vm/console.log" \
  >"$HOME/vm/qemu.out" 2>&1 &

echo "qemu pid $!"
echo "waiting for ssh on 2222 ..."
for i in $(seq 1 120); do
  if timeout 3 bash -c '</dev/tcp/127.0.0.1/2222' 2>/dev/null; then echo "ssh port open after ${i}0s"; break; fi
  sleep 10
done
echo "--- console tail ---"
tail -20 "$HOME/vm/console.log" 2>/dev/null
