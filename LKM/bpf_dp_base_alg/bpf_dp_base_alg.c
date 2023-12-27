#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>
#include <linux/bitops.h>

extern int register_btf_kfunc_id_set(enum bpf_prog_type prog_type, const struct btf_kfunc_id_set *kset);

__bpf_kfunc u64 bpf_ffs(u64 val) 
{
	return __ffs(val);
}
EXPORT_SYMBOL_GPL(bpf_ffs);


BTF_SET8_START(bpf_dp_base_alg_kfunc_ids)
BTF_ID_FLAGS(func, bpf_ffs)
BTF_SET8_END(bpf_dp_base_alg_kfunc_ids)

static const struct btf_kfunc_id_set bpf_dp_base_alg_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &bpf_dp_base_alg_kfunc_ids,
};

static int __init networking_dp_alg_set_init(void) {
        int ret;
        ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &bpf_dp_base_alg_kfunc_set);
	if (ret < 0) {
		pr_err("failed to reigster networking DP ALG kfunc set\n");
		return ret;
	}
        pr_info("register networking DP ALG set");
	return 0;
}

static void __exit networking_dp_alg_set_exit(void) {
	pr_info("unregister networking DP ALG set");
}

/* Register module functions */
module_init(networking_dp_alg_set_init);
module_exit(networking_dp_alg_set_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chonepieceyb");
MODULE_DESCRIPTION("BPF networking datapath base ALG kfunc sets");
MODULE_VERSION("0.01");