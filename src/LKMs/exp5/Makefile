USE_DEBUG ?= 0
GCC_VERSION ?= 11
CLANG_VERSION ?= 14.0.0
CC_SIMD_OPTS ?= -mavx2

obj-m += sk_cm_2.o
obj-m += sk_cm_4.o
obj-m += sk_cm_6.o
obj-m += sk_cm_8.o

ifeq ($(USE_DEBUG),1)
ccflags-y += -DCOUNTMIN_DEBUG
endif

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
