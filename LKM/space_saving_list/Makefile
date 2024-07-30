OBJ_NAME := space_saving_list
USE_DEBUG ?= 0

obj-m := ${OBJ_NAME}.o

KDIR_DBG ?= ../../linux
KDIR ?= /lib/modules/$(shell uname -r)/build

ifeq (${USE_DEBUG},1)
ccflags-y += -DSS_DEBUG
endif

default:
	bear -- make -C $(KDIR) M=$(PWD) modules
dbg:
	bear -- make -C $(KDIR_DBG) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean
test:
	-sudo rmmod $(OBJ_NAME)
	sudo dmesg -C
	sudo insmod $(OBJ_NAME).ko
	sudo dmesg
rm: 
	-sudo rmmod $(OBJ_NAME)
	sudo dmesg
