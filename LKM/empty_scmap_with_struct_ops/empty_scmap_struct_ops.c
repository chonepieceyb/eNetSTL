#include <linux/bpf_struct_ops_module.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/bpf_verifier.h>

#include "empty_scmap_with_callback.h"

#define BPF_MOD_STRUCT_OPS_TYPES(fn) fn(empty_scmap_struct_ops)

extern int
bpf_reg_module_struct_ops(struct bpf_module_struct_ops *mod_struct_ops);
extern int
bpf_unreg_module_struct_ops(struct bpf_module_struct_ops *mod_struct_ops);

/* Same as `empty_scmap_callback_ops` */
struct empty_scmap_struct_ops {
#if USE_CALLBACK_PARAM_COUNT == 0
	int (*callback)(void);
#elif USE_CALLBACK_PARAM_COUNT == 1
	int (*callback)(u64 param1);
#elif USE_CALLBACK_PARAM_COUNT == 5
	int (*callback)(u64 param1, u64 param2, u64 param3, u64 param4,
			u64 param5);
#else
#error "Unsupported USE_CALLBACK_PARAM_COUNT"
#endif
	struct module *owner;
};

/*
 * step3: implement struct bpf_struct_ops : 
 * 1. init 
 * 2. reg
 * 3. unreg 
 * 4. check_member
 * 5. init_member 
 * 6. set name to your module interface name, eg st_demo_ops here 
 * 7. set verifier_ops
 */

#if USE_CALLBACK_WORKAROUND == 1
static u32 callback_prog_fd = 0;
#endif

static int empty_scmap_struct_ops_init(struct btf *btf)
{
	return 0;
}

static int empty_scmap_struct_ops_check_member(const struct btf_type *t,
					       const struct btf_member *member,
					       const struct bpf_prog *prog)
{
	u32 moff;
	moff = __btf_member_bit_offset(t, member) / 8;
	switch (moff) {
	case offsetof(struct empty_scmap_struct_ops, callback):
		/* allow to set first_func */
		break;
	default:
		return -ENOTSUPP;
	}
	return 0;
}

static int empty_scmap_struct_ops_init_member(const struct btf_type *t,
					      const struct btf_member *member,
					      void *kdata, const void *udata)
{
	const struct empty_scmap_struct_ops *uop;
	struct empty_scmap_struct_ops *op;
	int prog_fd;
	u32 moff;

	uop = (const struct empty_scmap_struct_ops *)udata;
	op = (struct empty_scmap_struct_ops *)kdata;

	moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	/*check function member */
	case offsetof(struct empty_scmap_struct_ops, callback):
		goto func_member;
	default:
		return -EINVAL;
	}

func_member:
	prog_fd = (int)(*(unsigned long *)(udata + moff));
	if (!prog_fd)
		return -EINVAL;
#if USE_CALLBACK_WORKAROUND == 1
	else {
		/* It works because the callback is the only function member for now */
		pr_info("hash_mod_struct_ops: got callback fd %d\n", prog_fd);
		callback_prog_fd = prog_fd;
	}
#endif

	return 0;
}

static int empty_scmap_struct_ops_reg(void *kdata)
{
#if USE_CALLBACK_WORKAROUND == 1
	return empty_scmap_callback_register(
		(struct empty_scmap_callback_ops *)kdata, callback_prog_fd);
#else
	return empty_scmap_callback_register(
		(struct empty_scmap_callback_ops *)kdata);
#endif
}

static void empty_scmap_struct_ops_unreg(void *kdata)
{
	empty_scmap_callback_unregister(
		(struct empty_scmap_callback_ops *)kdata);
}

/* See $KERNEL/kernel/bpf/bpf_struct_ops.c */
extern const struct bpf_verifier_ops default_mod_stops_verifier_ops;

struct bpf_struct_ops bpf_empty_scmap_struct_ops = {
	.verifier_ops = &default_mod_stops_verifier_ops,
	.reg = empty_scmap_struct_ops_reg,
	.unreg = empty_scmap_struct_ops_unreg,
	.check_member = empty_scmap_struct_ops_check_member,
	.init_member = empty_scmap_struct_ops_init_member,
	.init = empty_scmap_struct_ops_init,
	.name = "empty_scmap_struct_ops",
};

BPF_MODULE_STRUCT_OPS_SEC(empty_scmap_struct_ops, BPF_MOD_STRUCT_OPS_TYPES);

static int __init empty_scmap_struct_ops_module_init(void)
{
	int ret;
	ret = bpf_reg_module_struct_ops(empty_scmap_struct_ops);
	if (ret < 0) {
		pr_err("empty_scmap_struct_ops: failed to register mod_struct_ops %s\n",
		       THIS_MODULE->name);
		return -1;
	}
	pr_err("empty_scmap_struct_ops: register mod_struct_ops %s\n",
	       THIS_MODULE->name);
	return 0;
}

static void __exit empty_scmap_struct_ops_module_exit(void)
{
	bpf_unreg_module_struct_ops(empty_scmap_struct_ops);
	pr_info("unregister mod_struct_ops %s\n", THIS_MODULE->name);
}

/* Register module functions */
module_init(empty_scmap_struct_ops_module_init);
module_exit(empty_scmap_struct_ops_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yang Hanlin");
MODULE_DESCRIPTION("Empty scmap module struct ops");
MODULE_VERSION("0.0.1");
