# TorShield kernel module + userspace control tool
obj-m := torshield.o

ccflags-y += -Wall -Wextra -Wno-unused-parameter

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(CURDIR)
CC   ?= gcc

all: module torshieldctl

module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

torshieldctl: torshieldctl.c
	$(CC) -Wall -Wextra -O2 -o torshieldctl torshieldctl.c

install: module torshieldctl
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	install -D -m 0755 torshieldctl $(DESTDIR)/usr/local/sbin/torshieldctl
	depmod -a

uninstall:
	rm -f $(DESTDIR)/lib/modules/$(shell uname -r)/extra/torshield.ko
	rm -f $(DESTDIR)/usr/local/sbin/torshieldctl
	depmod -a

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f torshieldctl

.PHONY: all module install uninstall clean
