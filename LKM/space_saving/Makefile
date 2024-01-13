OBJ_NAME := space_saving
USE_DEBUG ?= 1
USE_SIMD ?= 1
GCC_VERSION := 13

obj-m := ${OBJ_NAME}.o

KDIR_DBG ?= ../../linux
KDIR ?= /lib/modules/$(shell uname -r)/build

ifeq (${USE_DEBUG},1)
ccflags-y += -DSS_DEBUG
endif

ifeq (${USE_SIMD},1)
ccflags-y += -DSS_SIMD -I/usr/lib/gcc/x86_64-linux-gnu/$(GCC_VERSION)/include -mavx2 -mbmi
endif

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
