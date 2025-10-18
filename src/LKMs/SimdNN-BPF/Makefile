obj-m += simdnn.o
simdnn-objs := module.o simdnn_kfunc.o simdnn_lkm.o

# Use project's linux kernel source
KDIR := /root/projects/eNetSTL/linux/kernel

# Enable BTF and BPF support
ccflags-y := -I../../../bpf_kern/SimdNN-BPF
ccflags-y += -DBTF_ENABLED
# Disable warnings that prevent compilation
ccflags-y += -Wno-strict-prototypes -Wno-unknown-pragmas
# Enable SIMD support
ccflags-y += -O2 -march=native

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
