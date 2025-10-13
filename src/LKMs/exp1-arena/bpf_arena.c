#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>

__bpf_kfunc void bpf_arena_empty(void *p__map)
{	
	return;
}
EXPORT_SYMBOL_GPL(bpf_arena_empty);

BTF_KFUNCS_START(enetstl_arena_kfuncs)
BTF_ID_FLAGS(func, bpf_arena_empty, KF_TRUSTED_ARGS)
BTF_KFUNCS_END(enetstl_arena_kfuncs)

static const struct btf_kfunc_id_set enetset_arena_kfunc_set = {
	.owner = THIS_MODULE,
  	.set   = &enetstl_arena_kfuncs,
};

static int __init bpf_arena_init(void) {
	int ret;
        ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &enetset_arena_kfunc_set);
	if (ret < 0) {
		pr_err("failed to reigster enetstl arena kfuncs\n");
		return ret;
	}
        pr_info("register enetstl arena kfuncs");
	return 0;
}

static void __exit bpf_arena_exit(void) {
	pr_info("unregister enetstl arena kfuncs");
}

/* Register module functions */
module_init(bpf_arena_init);
module_exit(bpf_arena_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chonepieceyb");
MODULE_DESCRIPTION("BPF arena kfuncs");
MODULE_VERSION("0.0.1");
