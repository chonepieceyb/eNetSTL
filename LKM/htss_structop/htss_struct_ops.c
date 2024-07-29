#include <linux/bpf_struct_ops_module.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/bpf_verifier.h>

#include "htss_struct_ops.h"

extern const struct bpf_func_proto *
default_mod_stops_get_func_proto(enum bpf_func_id func_id,
			   const struct bpf_prog *prog);

extern bool default_mod_stops_is_valid_access(int off, int size, enum bpf_access_type type,
					const struct bpf_prog *prog,
					struct bpf_insn_access_aux *info);

extern int bpf_reg_module_struct_ops(struct bpf_module_struct_ops *mod_struct_ops);
extern int bpf_unreg_module_struct_ops(struct bpf_module_struct_ops *mod_struct_ops);

extern int reg_htss_structop_ops(struct htss_struct_ops *new_ext_ops);
extern void unreg_htss_structop_ops(struct htss_struct_ops *ops);

#define BPF_MOD_STRUCT_OPS_TYPES(fn)	\
fn(htss_struct_ops)					\

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

static const struct btf_type *ctx_type;
static u32 ctx_type_id;

static int htss_struct_ops_init(struct btf *btf)
{
	ctx_type_id = btf_find_by_name_kind(btf, "mod_struct_ops_ctx", BTF_KIND_STRUCT);
	if (ctx_type_id < 0)
		return -EINVAL;
	ctx_type = btf_type_by_id(btf, ctx_type_id);

	return 0;
}
    
static int htss_struct_ops_check_member(const struct btf_type *t,
				    const struct btf_member *member, const struct bpf_prog *prog)
{
        u32 moff; 
        moff = __btf_member_bit_offset(t, member) / 8;
        switch (moff) {
        case offsetof(struct htss_struct_ops, htss_loop_up_eBPF):
        case offsetof(struct htss_struct_ops, htss_update_eBPF):
	        /* allow to set first_func */
		break;
	default: 
	        return -ENOTSUPP;
        }
	return 0;
}

static int htss_struct_ops_init_member(const struct btf_type *t,
				   const struct btf_member *member,
				   void *kdata, const void *udata)
{
	const struct htss_struct_ops *uop;
	struct htss_struct_ops *op;
	int prog_fd;
	u32 moff;

	uop = (const struct htss_struct_ops *)udata;
	op = (struct htss_struct_ops *)kdata;

	moff = __btf_member_bit_offset(t, member) / 8;
	    
	switch (moff) {
        /*check function member */
	case offsetof(struct htss_struct_ops, htss_loop_up_eBPF):
		goto func_member;
	case offsetof(struct htss_struct_ops, htss_update_eBPF):
		goto func_member;
	default:
		return -EINVAL;
	}

    
func_member:
	prog_fd = (int)(*(unsigned long *)(udata + moff));
	if (!prog_fd)
		return -EINVAL;

	return 0;
}

static int  htss_struct_ops_reg(void *kdata)
{
	return reg_htss_structop_ops(kdata);
}

static void htss_struct_ops_unreg(void *kdata) 
{
	unreg_htss_structop_ops(kdata);
}

static int default_mod_stops_btf_struct_access(struct bpf_verifier_log *log,
					const struct bpf_reg_state *reg,
					int off, int size)
{
	const struct btf_type *t;
	size_t end;

	t = btf_type_by_id(reg->btf, reg->btf_id);
	if (t != ctx_type) {
		bpf_log(log, "only read is supported\n");
		return -EACCES;
	}

	switch (off) {
	case offsetof(struct mod_struct_ops_ctx, res):
		end = offsetofend(struct mod_struct_ops_ctx, res);
		break;
	default:
		bpf_log(log, "no write support to mod_struct_ops_ctx at off %d\n", off);
		return -EACCES;
	}

	if (off + size > end) {
		bpf_log(log,
			"write access at off %d with size %d beyond the member of mod_struct_ops_ctx ended at %zu\n",
			off, size, end);
		return -EACCES;
	}

	return 0;
}


const struct bpf_verifier_ops demo_mod_stops_verifier_ops = {
	.get_func_proto		= default_mod_stops_get_func_proto,
	.is_valid_access	= default_mod_stops_is_valid_access,
	.btf_struct_access	= default_mod_stops_btf_struct_access,
};


struct bpf_struct_ops bpf_htss_struct_ops = {
	.verifier_ops = &demo_mod_stops_verifier_ops,
	.reg = htss_struct_ops_reg,
	.unreg = htss_struct_ops_unreg,
	.check_member = htss_struct_ops_check_member,
	.init_member = htss_struct_ops_init_member,
	.init = htss_struct_ops_init,
	.name = "htss_struct_ops",
};

BPF_MODULE_STRUCT_OPS_SEC(demo_mod_struct_ops, BPF_MOD_STRUCT_OPS_TYPES)

static int __init mod_stops_init(void) {
        int ret;
	ret = bpf_reg_module_struct_ops(demo_mod_struct_ops);
	if (ret < 0) {
		pr_err("failed to reigster mod_struct_ops %s\n", THIS_MODULE->name);
		return -1;
	}
	pr_err("reigster mod_struct_ops %s\n", THIS_MODULE->name);
	return 0;
}

static void __exit mod_stops_exit(void) {
	bpf_unreg_module_struct_ops(demo_mod_struct_ops);
        pr_info("unregister mod_struct_ops %s\n", THIS_MODULE->name);
}

/* Register module functions */
module_init(mod_stops_init);
module_exit(mod_stops_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chonepieceyb");
MODULE_DESCRIPTION("A simple bpf module struct ops demo.");
MODULE_VERSION("0.01");
