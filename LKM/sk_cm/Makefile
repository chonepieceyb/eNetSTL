OBJ_NAME := sk_cm
FASTHASH_INLINE := 1
XXHASH_INLINE := 1
GCC_VERSION := 13

obj-m := $(OBJ_NAME).o 

ifneq ($(FASTHASH_INLINE),1)
$(OBJ_NAME)-objs += fasthash_simd.o
endif

ifneq ($(XXHASH_INLINE),1)
$(OBJ_NAME)-objs += xxhash_simd.o
endif

# FIXME: This is not portable
ifeq ($(FASTHASH_INLINE),1)
ccflags-y += -DFASTHASH_INLINE -I/usr/lib/gcc/x86_64-linux-gnu/$(GCC_VERSION)/include -mavx2
else
CFLAGS_fasthash_simd.o += -I/usr/lib/gcc/x86_64-linux-gnu/$(GCC_VERSION)/include -mavx2
endif

ifeq ($(XXHASH_INLINE),1)
ccflags-y += -DXXHASH_INLINE -I/usr/lib/gcc/x86_64-linux-gnu/$(GCC_VERSION)/include -mavx2
else
CFLAGS_xxhash_simd.o += -I/usr/lib/gcc/x86_64-linux-gnu/$(GCC_VERSION)/include -mavx2
endif

#KDIR ?= /home/chonepieceyb/CODING/Src/linux-6.0
KDIR ?= /lib/modules/$(shell uname -r)/build

default:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean
test:
	# We put a — in front of the rmmod command to tell make to ignore
	# an error in case the module isn’t loaded.
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

