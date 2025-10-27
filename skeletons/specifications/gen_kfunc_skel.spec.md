TODO: this scripts generates code snippets by inheriting from CommonSkeleton class in skeleton

## __init__ , class member parameters 
1. subproject: name of the subproject, no default value
2. kfunc_name: name of the kfunc, default is your_kfunc
3. author_name: author name, no default
4. version: version number, no default

## for skel_bpf_header_sec
parms: 
    kfunc_name: name of the kfunc, default is your_kfunc 
generate: 

```c
void $kfunc_name(void) __ksym;
```

## for skel_lkm_header_sec
param:
    none 
generate: 

```c
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>
```

## for skel_lkm_impl_sec
param:
    kfunc_name: name of the kfunc, default is your_kfunc 
    subproject: name of the subproject, no default value
generate:

```c     
__bpf_kfunc_start_defs();
__bpf_kfunc void $kfunc_name(void)
{
	return;
}
__bpf_kfunc_end_defs();

BTF_KFUNCS_START($subproject_kfuncs)
BTF_ID_FLAGS(func, $kfunc_name)
BTF_KFUNCS_END($subproject_kfuncs)

static const struct btf_kfunc_id_set $subproject_kfunc_set = {
 	    .owner = THIS_MODULE,
   	    .set   = &$subproject_kfuncs,
};
```

### for skel_lkm_init_exit
params:
    subproject: name of the subproject, no default value
    author_name: author name, no default
    version: version number, no default
generate:

```c
static int __init $subproject_init(void) {
	int ret;
        ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &$subproject_kfunc_set);
	if (ret < 0) {
		pr_err("failed to reigster $subproject kfuncs\n");
		return ret;
	}
        pr_info("register $subproject kfuncs");
	return 0;
}

static void __exit $subproject_exit(void) {
	pr_info("unregister $subproject kfuncs");
}

/* Register module functions */
module_init($subproject_init);
module_exit($subproject_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("$author_name");
MODULE_DESCRIPTION("$subproject kfuncs");
MODULE_VERSION("$version");
```

### for skel_lkm_makefile
params:
    subproject: name of the subproject, no default value
generate:

```makefile
obj-m += ${subproject}.o
${subproject}-objs := module.o

KDIR_DBG ?= /mnt/disk1/yangbin/CODING/WorkSpace/linux_testbed/linux
KDIR ?= /lib/modules/$(shell uname -r)/build

default:
	bear -- make -C $(KDIR) M=$(PWD) modules
dbg:
	bear -- make -C $(KDIR_DBG) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean
test:
	# We put a — in front of the rmmod command to tell make to ignore
	# an error in case the module isn't loaded.
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

```

