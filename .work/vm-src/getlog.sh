dmesg | grep -iE 'drop reason|non-peer|oops|BUG:|panic' | head -40
echo "---- stats ----"
grep -E 'tun_|dev_' /proc/torshield/stats
echo "---- dev ----"
ip -n n1 -s link show torshield0 | tail -4
