#include <linux/bpf_struct_ops_module.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/bpf_verifier.h>
#include "mod_struct_ops_demo.h"

extern const struct bpf_func_proto *
default_mod_stops_get_func_proto(enum bpf_func_id func_id,
			   const struct bpf_prog *prog);

extern bool default_mod_stops_is_valid_access(int off, int size, enum bpf_access_type type,
					const struct bpf_prog *prog,
					struct bpf_insn_access_aux *info);

extern int bpf_reg_module_struct_ops(struct bpf_module_struct_ops *mod_struct_ops);
extern int bpf_unreg_module_struct_ops(struct bpf_module_struct_ops *mod_struct_ops);

extern int reg_cmap_ext_demo_ops(struct mod_struct_ops_demo *new_ext_ops , int hw_prog_fd);
extern void unreg_cmap_ext_demo_ops(struct mod_struct_ops_demo *ops);

#define BPF_MOD_STRUCT_OPS_TYPES(fn)	\
fn(mod_struct_ops_demo)					\

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

static int hw_prog_fd = 0;

static int mod_struct_ops_demo_init(struct btf *btf)
{
	ctx_type_id = btf_find_by_name_kind(btf, "mod_struct_ops_ctx", BTF_KIND_STRUCT);
	if (ctx_type_id < 0)
		return -EINVAL;
	ctx_type = btf_type_by_id(btf, ctx_type_id);

	return 0;
}
    
static int mod_struct_ops_demo_check_member(const struct btf_type *t,
				    const struct btf_member *member, const struct bpf_prog *prog)
{
        u32 moff; 
        moff = __btf_member_bit_offset(t, member) / 8;
        switch (moff) {
        case offsetof(struct mod_struct_ops_demo, hello_world):
	        /* allow to set first_func */
		break;
	default: 
	        return -ENOTSUPP;
        }
	return 0;
}

static int mod_struct_ops_demo_init_member(const struct btf_type *t,
				   const struct btf_member *member,
				   void *kdata, const void *udata)
{
	const struct mod_struct_ops_demo *uop;
	struct mod_struct_ops_demo *op;
	int prog_fd;
	u32 moff;

	uop = (const struct mod_struct_ops_demo *)udata;
	op = (struct mod_struct_ops_demo *)kdata;

	moff = __btf_member_bit_offset(t, member) / 8;
	    
	switch (moff) {
        /*check function member */
	case offsetof(struct mod_struct_ops_demo, hello_world):
		pr_info("hello world prog fd %d\n", (int)(*(unsigned long *)(udata + moff)));
		hw_prog_fd = (int)(*(unsigned long *)(udata + moff));
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

static int  mod_struct_ops_demo_reg(void *kdata)
{
	return reg_cmap_ext_demo_ops(kdata, hw_prog_fd);
}

static void mod_struct_ops_demo_unreg(void *kdata) 
{
	unreg_cmap_ext_demo_ops(kdata);
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
	case offsetof(struct mod_struct_ops_ctx, val):
		end = offsetofend(struct mod_struct_ops_ctx, val);
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


struct bpf_struct_ops bpf_mod_struct_ops_demo = {
	.verifier_ops = &demo_mod_stops_verifier_ops,
	.reg = mod_struct_ops_demo_reg,
	.unreg = mod_struct_ops_demo_unreg,
	.check_member = mod_struct_ops_demo_check_member,
	.init_member = mod_struct_ops_demo_init_member,
	.init = mod_struct_ops_demo_init,
	.name = "mod_struct_ops_demo",
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
