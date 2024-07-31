obj-m += empty_scmap_with_callback.o
obj-m += empty_scmap_struct_ops.o
obj-m += empty_primitive.o

#KDIR ?= /home/chonepieceyb/CODING/Src/linux-6.0
KDIR_DBG ?= /mnt/disk1/yangbin/CODING/WorkSpace/linux_testbed/linux
KDIR ?= /lib/modules/$(shell uname -r)/build

default:
	bear -- make -C $(KDIR) M=$(PWD) modules
dbg:
	bear -- make -C $(KDIR_DBG) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean
test:j
	-sudo rmmod $(OBJ_NAME)
	sudo dmesg -C
	sudo insmod $(OBJ_NAME).ko
	sudo dmesg
rm: 
	-sudo rmmod $(OBJ_NAME)
	sudo dmesg
