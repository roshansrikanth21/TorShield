#!/bin/bash
# Launch the VM detached; do not wait.
set -u
Q=$HOME/qemu
export LD_LIBRARY_PATH="$Q/root/usr/lib/x86_64-linux-gnu:$Q/root/lib/x86_64-linux-gnu:$Q/root/usr/lib"
QE="$Q/root/usr/bin/qemu-system-x86_64"
export QEMU_MODULE_DIR="$Q/root/usr/lib/x86_64-linux-gnu/qemu"

pkill -f 'qemu-system-x86_64.*disk.qcow2' 2>/dev/null
sleep 1
[ -f "$HOME/vm/disk.qcow2" ] || "$Q/root/usr/bin/qemu-img" create -f qcow2 -F qcow2 -b "$HOME/vm/noble.img" "$HOME/vm/disk.qcow2" 40G

if ! ss -ltn 2>/dev/null | grep -q ':8000 '; then
  ( cd "$HOME/vm/seed" && setsid nohup python3 -m http.server 8000 --bind 0.0.0.0 >"$HOME/vm/http.log" 2>&1 < /dev/null & )
  sleep 1
fi

setsid nohup "$QE" \
  -machine pc -accel tcg -cpu max -smp 2 -m 2048 \
  -L "$Q/root/usr/share/qemu" \
  -drive file="$HOME/vm/disk.qcow2",if=virtio,cache=writeback \
  -netdev user,id=n0,hostfwd=tcp::2222-:22 -device virtio-net-pci,netdev=n0,romfile= \
  -smbios type=1,serial='ds=nocloud-net;s=http://10.0.2.2:8000/' \
  -display none -serial file:"$HOME/vm/console.log" \
  >"$HOME/vm/qemu.out" 2>&1 < /dev/null &

sleep 3
echo "started:"; pgrep -af 'qemu-system-x86_64' | head -2
echo "--- qemu.out ---"; cat "$HOME/vm/qemu.out"
echo "--- http ---"; ss -ltn | grep 8000 || echo "http not listening"
