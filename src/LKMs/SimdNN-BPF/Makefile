obj-m += simdnn.o
simdnn-objs := module.o simdnn_kfunc.o simdnn_lkm.o

# Use project's linux kernel source
KDIR := /root/projects/eNetSTL/linux/kernel

# Enable BTF and BPF support
ccflags-y := -I../../../bpf_kern/SimdNN-BPF
ccflags-y += -DBTF_ENABLED
# Disable warnings that prevent compilation
ccflags-y += -Wno-strict-prototypes -Wno-unknown-pragmas
# Disable SIMD/AVX support for kernel compatibility
ccflags-y += -O2 -U__AVX2__ -U__SSE2__ -U__SSE__

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
