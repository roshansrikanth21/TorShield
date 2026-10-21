#!/bin/bash
set -u
ls -l "$HOME/kdeb" | head -20
echo "--- extracted trees ---"
ls -d "$HOME/kernels"/*/usr/src/* 2>/dev/null
echo "--- ubsan present? ---"
for f in "$HOME"/kernels/*/usr/src/*/scripts/Makefile.ubsan; do echo "$f"; done
