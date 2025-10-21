obj-m += simdnn.o
simdnn-objs := module.o simdnn_kfunc.o

ifeq ($(LLVM),1)
ccflags-y += -I/usr/lib/llvm-$(shell echo $(CLANG_VERSION) | cut -d. -f1)/lib/clang/$(CLANG_VERSION)/include $(CC_SIMD_OPTS)
else
ccflags-y += -I/usr/lib/gcc/x86_64-linux-gnu/$(GCC_VERSION)/include $(CC_SIMD_OPTS) -g
endif

# 仅对 simdnn_kfunc.o 生效
CFLAGS_simdnn_kfunc.o += -mavx2 -msse4.1 -mfpmath=sse -fno-tree-vectorize
CFLAGS_simdnn_kfunc.o += -isystem $(shell $(CC) -print-file-name=include)

# 关键：跳过 mm_malloc.h（否则它会 #include <stdlib.h>）
CFLAGS_simdnn_kfunc.o += -D_MM_MALLOC_H_INCLUDED=1

# 可选：避免误升到 AVX-512
CFLAGS_simdnn_kfunc.o += -mno-avx512f -mno-avx512vl -mno-avx512bw -mno-avx512dq

KDIR_DBG ?= /mnt/disk1/yangbin/CODING/WorkSpace/linux_testbed/linux
KDIR ?= /lib/modules/$(shell uname -r)/build

default:
	bear -- make -C $(KDIR) M=$(PWD) modules
dbg:
	bear -- make -C $(KDIR_DBG) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean
test:
	# We put a — in front of the rmmod command to tell make to ignore
	# an error in case the module isn't loaded.
	-sudo rmmod $(OBJ_NAME)
	# Clear the kernel log without echo
	sudo dmesg -C
	# Insert the module
	sudo insmod $(OBJ_NAME).ko
	# Display the kernel log
	sudo dmesg
rm: 
	-sudo rmmod $(OBJ_NAME)
	sudo dmesg
