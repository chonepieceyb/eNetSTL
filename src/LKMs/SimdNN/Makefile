# Makefile for SimdNN-SIMD operations module

obj-m += simd_ops.o
simd_ops-objs := simd_ops.o

# Compiler flags
CC_SIMD_OPTS ?= -mavx2 -mbmi -march=native

ccflags-y := -I$(src)/.. -I$(src)/../eNetSTL $(CC_SIMD_OPTS) \
             -Wall -Wextra -Wno-unused-function -Wno-unused-parameter \
             -O2 -fno-strict-aliasing -fno-common

# Debug flags
ifeq ($(DEBUG),1)
ccflags-y += -g -DDEBUG -O0
endif

# Kernel build directory
KDIR := /lib/modules/$(shell uname -r)/build

# Default target
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Clean target
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f *.o *.ko *.mod.c *.symvers *.order

# Install target
install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

# Load module
load:
	sudo insmod simd_ops.ko

# Unload module
unload:
	sudo rmmod simd_ops

# Check if module is loaded
status:
	lsmod | grep simd_ops

# View kernel log
dmesg:
	dmesg | tail -20

.PHONY: all clean install load unload status dmesg