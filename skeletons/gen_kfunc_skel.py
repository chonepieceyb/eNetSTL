#!/usr/bin/env python3
"""
This script generates kfunc skeleton code by inheriting from CommonSkeleton class.
Generates kfunc BPF programs and corresponding LKM.
"""

from skels_common import CommonSkeleton


class KfuncSkeleton(CommonSkeleton):
    """Generates kfunc program skeleton code snippets."""

    def __init__(self, subproject: str = "", kfunc_name: str = "your_kfunc",
                 author_name: str = "", version: str = ""):
        super().__init__(subproject, author_name, version)
        self.kfunc_name = kfunc_name

    def skel_bpf_header_sec(self, **kwargs) -> str:
        """Generate BPF header with kfunc declaration."""
        kfunc_name = kwargs.get('kfunc_name', self.kfunc_name)
        return f"void {kfunc_name}(void) __ksym;"

    def skel_lkm_header_sec(self, **kwargs) -> str:
        """Generate LKM header section."""
        return """#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>"""

    def skel_lkm_impl_sec(self, **kwargs) -> str:
        """Generate LKM implementation section."""
        kfunc_name = kwargs.get('kfunc_name', self.kfunc_name)
        subproject = kwargs.get('subproject', self.subproject)
        return f"""
__bpf_kfunc_start_defs();
__bpf_kfunc void {kfunc_name}(void)
{{
	return;
}}
__bpf_kfunc_end_defs();

BTF_KFUNCS_START({subproject}_kfuncs)
BTF_ID_FLAGS(func, {kfunc_name})
BTF_KFUNCS_END({subproject}_kfuncs)

static const struct btf_kfunc_id_set {subproject}_kfunc_set = {{
 	    .owner = THIS_MODULE,
   	    .set   = &{subproject}_kfuncs,
}};"""

    def skel_lkm_init_exit(self, **kwargs) -> str:
        """Generate LKM initialization and exit functions."""
        subproject = kwargs.get('subproject', self.subproject)
        author_name = kwargs.get('author_name', self.author_name)
        version = kwargs.get('version', self.version)
        return f"""static int __init {subproject}_init(void) {{
	int ret;
        ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &{subproject}_kfunc_set);
	if (ret < 0) {{
		pr_err("failed to reigster {subproject} kfuncs\\n");
		return ret;
	}}
        pr_info("register {subproject} kfuncs");
	return 0;
}}

static void __exit {subproject}_exit(void) {{
	pr_info("unregister {subproject} kfuncs");
}}

/* Register module functions */
module_init({subproject}_init);
module_exit({subproject}_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("{author_name}");
MODULE_DESCRIPTION("{subproject} kfuncs");
MODULE_VERSION("{version}");"""

    def skel_lkm_makefile(self, **kwargs) -> str:
        """Generate LKM Makefile."""
        subproject = kwargs.get('subproject', self.subproject)
        return f"""obj-m += {subproject}.o
{subproject}-objs := module.o

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
	sudo dmesg"""


if __name__ == "__main__":
    # Example usage
    skeleton = KfuncSkeleton("example_subproject", "example_kfunc", "Author Name", "1.0.0")
    print("=== BPF Header Section ===")
    print(skeleton.skel_bpf_header_sec())
    print("\n=== LKM Header Section ===")
    print(skeleton.skel_lkm_header_sec())
    print("\n=== LKM Implementation Section ===")
    print(skeleton.skel_lkm_impl_sec())
    print("\n=== LKM Init/Exit Section ===")
    print(skeleton.skel_lkm_init_exit())
    print("\n=== LKM Makefile ===")
    print(skeleton.skel_lkm_makefile())