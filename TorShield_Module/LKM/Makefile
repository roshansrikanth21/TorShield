# TorShield kernel module + userspace control tool
obj-m := torshield.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)
CC   ?= gcc

all: module torshieldctl

module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

torshieldctl: torshieldctl.c
	$(CC) -Wall -O2 -o torshieldctl torshieldctl.c

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f torshieldctl

.PHONY: all module clean
