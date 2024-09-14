OBJ_NAME := eNetSTL
GCC_VERSION ?= 11
CLANG_VERSION ?= 14.0.0
CC_SIMD_OPTS ?= -mavx2 -mbmi

obj-m := ${OBJ_NAME}.o

${OBJ_NAME}-objs := module.o
${OBJ_NAME}-objs += bkt_list.o
${OBJ_NAME}-objs += bkt_list_rust.o
${OBJ_NAME}-objs += geo_sampling.o


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
