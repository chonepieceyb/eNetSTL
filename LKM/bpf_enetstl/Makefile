MODNAME= bpf_enetstl
#MODNAME_IMPL = bpf_enetstl_impl

KDIR ?= /mnt/disk1/yangbin/CODING/WorkSpace/linux_testbed/linux
BUILD_TYPE = release

obj-m := $(MODNAME).o
$(MODNAME)-objs := bpf_enetstl_rust.o bpf_enetstl_api.o
#obj-m += $(MODNAME).o

#$(MODNAME_IMPL)-objs := bpf_enetstl_rust.o
#$(MODNAME)-objs := bpf_enetstl_api.o


# obj-m := $(MODNAME_API).o
# #$(MODNAME)-objs := bpf_enetstl_api.o bpf_enetstl_impl.o
# $(MODNAME)-objs := bpf_enetstl_api.o

all:
	$(MAKE) LLVM=1 -C $(KDIR) M=$(CURDIR)

clean:
	$(MAKE) LLVM=1  -C $(KDIR) M=$(CURDIR) clean