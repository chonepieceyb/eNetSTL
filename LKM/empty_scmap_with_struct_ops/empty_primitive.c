#include <linux/module.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>

#if USE_CALLBACK_PARAM_COUNT == 0
__bpf_kfunc int empty_primitive(void)
{
	return 0;
}
#elif USE_CALLBACK_PARAM_COUNT == 1
__bpf_kfunc int empty_primitive(u64 param1)
{
	return 0;
}
#elif USE_CALLBACK_PARAM_COUNT == 5
__bpf_kfunc int empty_primitive(u64 param1, u64 param2, u64 param3, u64 param4,
				u64 param5)
{
	return 0;
}
#else
#error "Unsupported USE_CALLBACK_PARAM_COUNT"
#endif
EXPORT_SYMBOL_GPL(empty_primitive);

BTF_SET8_START(empty_primitive_kfunc_ids)
BTF_ID_FLAGS(func, empty_primitive)
BTF_SET8_END(empty_primitive_kfunc_ids)

static const struct btf_kfunc_id_set empty_primitive_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &empty_primitive_kfunc_ids,
};

static int register_kfuncs(void)
{
	int ret;
	if ((ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					     &empty_primitive_kfunc_set)) !=
	    0) {
		return ret;
	}

	return 0;
}

static int __init empty_primitive_init(void)
{
	int ret;

	if ((ret = register_kfuncs()) != 0) {
		pr_err("empty_primitive: failed to register kfunc set: %d\n",
		       ret);
		return ret;
	} else {
		pr_info("empty_primitive: registered kfunc set\n");
	}

	pr_info("empty_primitive: initialized\n");
	return 0;
}

static void __exit empty_primitive_exit(void)
{
	pr_info("empty_primitive: exiting\n");
}

module_init(empty_primitive_init);
module_exit(empty_primitive_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yang Hanlin");
MODULE_DESCRIPTION("An empty kfunc to call from BPF programs");
MODULE_VERSION("0.0.1");
