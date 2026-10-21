# SPDX-License-Identifier: GPL-2.0
#
# Build the TC egress classifier and its loader.  The kernel module itself is
# built by the parent Makefile.

CLANG ?= clang
CC ?= gcc
MULTIARCH := $(shell gcc -print-multiarch 2>/dev/null)
BPF_CFLAGS := -target bpf -O2 -g -Wall -Wextra
ifneq ($(MULTIARCH),)
BPF_CFLAGS += -I/usr/include/$(MULTIARCH)
endif

all: torshield_tc.o torshield-tc

torshield_tc.o: torshield_tc.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

torshield-tc: torshield_tc_load.c
	$(CC) -O2 -g -Wall -Wextra -o $@ $< -lbpf -lelf -lz

clean:
	rm -f torshield_tc.o torshield-tc

.PHONY: all clean
