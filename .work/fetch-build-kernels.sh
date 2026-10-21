#!/bin/bash
# Fetch real Ubuntu kernel header trees into $HOME (no root needed) and build
# both TorShield module versions against each.  This is a genuine kbuild test.
set -u
BASE=$HOME/kernels
DL=$HOME/kdeb
mkdir -p "$BASE" "$DL"

fetch_build() {
  local ver="$1"           # e.g. 6.8.0-147
  local arch="$2"          # generic
  local pre="$BASE/$ver"
  local kdir="$pre/usr/src/linux-headers-$ver-$arch"
  echo "================ $ver-$arch ================"
  if [ ! -d "$kdir" ]; then
    ( cd "$DL" || exit 1
      apt-get download "linux-headers-$ver" "linux-headers-$ver-$arch" 2>&1 | tail -2
      for d in "linux-headers-${ver}_"*.deb "linux-headers-${ver}-${arch}_"*.deb; do
        [ -f "$d" ] && dpkg-deb -x "$d" "$pre"
      done
    )
  fi
  if [ ! -d "$kdir" ]; then echo "HEADERS MISSING for $ver"; return 1; fi
  echo "kdir: $kdir"

  for src in /mnt/k/tor-project/module/LKM /mnt/k/tor-project/original_repo/LKM; do
    local name; name=$(basename "$(dirname "$src")")
    local work="$HOME/bt/$ver-$name"
    rm -rf "$work"; mkdir -p "$work"
    cp "$src"/*.c "$src"/Makefile "$work"/ 2>/dev/null
    echo "---- build $name @ $ver ----"
    ( cd "$work" && make KDIR="$kdir" 2>&1 | grep -vE "^(make(\[1\])?: (Entering|Leaving)|  (CC|LD|MODPOST|GEN|CALL|UPD|WRAP|HOSTCC|HOSTLD))" )
    echo "exit=$? ko=$(ls "$work"/*.ko 2>/dev/null | wc -l)"
  done
}

fetch_build 6.8.0-147 generic
fetch_build 6.17.0-42 generic
