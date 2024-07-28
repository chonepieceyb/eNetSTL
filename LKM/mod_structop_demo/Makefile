obj-m := mod_struct_ops_demo.o
obj-m += cmap_ext_demo.o
#lkm_example-y := x.o

#KDIR ?= /home/chonepieceyb/CODING/Src/linux-6.0
KDIR_DBG ?= /mnt/disk1/yangbin/CODING/WorkSpace/linux_testbed/linux
KDIR ?= /lib/modules/$(shell uname -r)/build

default:
	bear -- make -C $(KDIR) M=$(PWD) modules
dbg:
	bear -- make -C $(KDIR_DBG) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean
clean_dbg:
	make -C $(KDIR_DBG) M=$(PWD) clean
test:
	# We put a — in front of the rmmod command to tell make to ignore
	# an error in case the module isn’t loaded.
	-sudo rmmod mod_struct_ops_demo
	-sudo rmmod cmap_ext_demo
	# Clear the kernel log without echo
	sudo dmesg -C
	# Insert the module
	sudo insmod cmap_ext_demo.ko
	sudo insmod mod_struct_ops_demo.ko
	# Display the kernel log
	sudo dmesg

