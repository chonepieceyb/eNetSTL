OBJ_NAME := bpf_arena
USE_DEBUG ?= 0
USE_PREFILL ?= 0
# GCC_VERSION ?= 13
# CLANG_VERSION ?= 14.0.0

obj-m := ${OBJ_NAME}.o

KDIR_DBG ?= /mnt/disk1/yangbin/CODING/WorkSpace/linux_testbed/linux
KDIR ?= /lib/modules/$(shell uname -r)/build

default:
	bear -- make -C $(KDIR) M=$(PWD) modules
dbg:
	bear -- make -C $(KDIR_DBG) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean
