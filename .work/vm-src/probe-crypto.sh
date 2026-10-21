#!/bin/sh
sudo modprobe chacha20poly1305 2>&1
echo "--- modinfo ---"
modinfo chacha20poly1305 2>&1 | head -4
echo "--- rfc7539 ---"
grep -A9 "name.*rfc7539" /proc/crypto
echo "--- chacha20poly1305 ---"
grep -A9 "name.*chacha20poly1305" /proc/crypto
echo "--- gcm(aes) impl ---"
grep -A9 "name.*: gcm" /proc/crypto | head -24
