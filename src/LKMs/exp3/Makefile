OBJ_NAME := cuckoo_hash
USE_DEBUG ?= 0
USE_PREFILL ?= 0
GCC_VERSION ?= 13
CLANG_VERSION ?= 14.0.0
CC_SIMD_OPTS ?= -DCUCKOO_HASH_SIMD -mavx2 -mbmi

obj-m := ${OBJ_NAME}.o

ccflags-y += -DCUCKOO_HASH_SIMD_KEY_CMP
ccflags-y += -DCUCKOO_HASH_SIMD_OTHER_CMP
ccflags-y += -DCUCKOO_HASH_USE_CRC

ifeq (${USE_DEBUG},1)
ccflags-y += -DCUCKOO_HASH_DEBUG
endif

ifeq (${USE_PREFILL},1)
ccflags-y += -DCUCKOO_HASH_PREFILL
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
