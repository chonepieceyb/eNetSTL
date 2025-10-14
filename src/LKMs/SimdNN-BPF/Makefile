obj-m += simdnn.o
simdnn-objs := module.o simdnn_kfunc.o simdnn_lkm.o

KDIR := /lib/modules/$(shell uname -r)/build

# Enable BTF and BPF support
ccflags-y := -I$(src)/../../../bpf_kern/SimdNN-BPF
ccflags-y += -DBTF_ENABLED

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean