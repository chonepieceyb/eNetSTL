GCC_VERSION ?= 11
CLANG_VERSION ?= 14.0.0
CC_SIMD_OPTS ?= -msse4.2

obj-m += sk_nitro_2.o
obj-m += sk_nitro_4.o
obj-m += sk_nitro_6.o
obj-m += sk_nitro_8.o
obj-m += sk_nitro_10.o

ifeq ($(LLVM),1)
ccflags-y += -I/usr/lib/llvm-$(shell echo $(CLANG_VERSION) | cut -d. -f1)/lib/clang/$(CLANG_VERSION)/include $(CC_SIMD_OPTS)
else
ccflags-y += -I/usr/lib/gcc/x86_64-linux-gnu/$(GCC_VERSION)/include $(CC_SIMD_OPTS)
endif

KDIR_DBG ?= /mnt/disk1/yangbin/CODING/WorkSpace/linux_testbed/linux
KDIR ?= /lib/modules/$(shell uname -r)/build

default:
	bear -- make -C $(KDIR) M=$(PWD) modules
dbg:
	bear -- make -C $(KDIR_DBG) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean
