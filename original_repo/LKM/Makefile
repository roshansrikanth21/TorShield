# Kernel module
obj-m := xor_obfuscation.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
CC := gcc

all:
	# Compile the kernel module
	make -C $(KDIR) M=$(PWD) modules
	# Compile the CLI tool
	$(CC) -o xorctl xorctl.c

clean:
	# Clean up generated files
	make -C $(KDIR) M=$(PWD) clean
	rm -f xorctl