#!/bin/bash
for k in 6.8.0-147 6.17.0-42; do
  d=$(ls -d "$HOME/kernels/$k/usr/src/linux-headers-$k-generic" 2>/dev/null)
  echo "== $k : $d =="
  grep -rl 'skb_gso_segment' "$d/include" 2>/dev/null | head -5
  echo -n "asm/unaligned.h: "; ls "$d/arch/x86/include/asm/unaligned.h" 2>&1 | tail -1
  echo -n "linux/unaligned.h: "; ls "$d/include/linux/unaligned.h" 2>&1 | tail -1
  echo -n "net/gso.h: "; ls "$d/include/net/gso.h" 2>&1 | tail -1
  echo -n "skb_checksum_help in skbuff.h: "; grep -c 'skb_checksum_help' "$d/include/linux/skbuff.h" 2>/dev/null
done
