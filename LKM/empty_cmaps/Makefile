OBJ_NAME := empty_cmap

obj-m := ${OBJ_NAME}.o
#lkm_example-y := x.o

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