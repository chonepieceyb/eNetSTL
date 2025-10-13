obj-m += simdnn_kfunc.o

simdnn_kfunc-objs := simdnn_kfunc.o

KDIR := /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean