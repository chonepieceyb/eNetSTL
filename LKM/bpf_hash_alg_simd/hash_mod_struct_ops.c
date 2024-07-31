#include <linux/bpf_struct_ops_module.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/bpf_verifier.h>

#include "hash_callback.h"

#define BPF_MOD_STRUCT_OPS_TYPES(fn) fn(hash_mod_struct_ops)

extern int
bpf_reg_module_struct_ops(struct bpf_module_struct_ops *mod_struct_ops);
extern int
bpf_unreg_module_struct_ops(struct bpf_module_struct_ops *mod_struct_ops);

#define HASH_MOD_STRUCT_OPS_CTX_SIZE 16384

struct hash_mod_struct_ops_ctx {
	u8 data[HASH_MOD_STRUCT_OPS_CTX_SIZE];
} __attribute__((packed));

struct hash_mod_struct_ops {
	int (*callback)(struct hash_mod_struct_ops_ctx *ctx, int i, u32 hash);
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

static const struct btf_type *ctx_type;
static u32 ctx_type_id;
static u32 callback_prog_fd = 0;

static int hash_mod_struct_ops_init(struct btf *btf)
{
	ctx_type_id = btf_find_by_name_kind(btf, "hash_mod_struct_ops_ctx",
					    BTF_KIND_STRUCT);
	if (ctx_type_id < 0) {
		pr_err("hash_mod_struct_ops: failed to find BTF type ID for struct hash_mod_struct_ops_ctx\n");
		return -EINVAL;
	}
	ctx_type = btf_type_by_id(btf, ctx_type_id);

	return 0;
}

static int hash_mod_struct_ops_check_member(const struct btf_type *t,
					    const struct btf_member *member,
					    const struct bpf_prog *prog)
{
	u32 moff;
	moff = __btf_member_bit_offset(t, member) / 8;
	switch (moff) {
	case offsetof(struct hash_mod_struct_ops, callback):
		/* allow to set first_func */
		break;
	default:
		return -ENOTSUPP;
	}
	return 0;
}

static int hash_mod_struct_ops_init_member(const struct btf_type *t,
					   const struct btf_member *member,
					   void *kdata, const void *udata)
{
	const struct hash_mod_struct_ops *uop;
	struct hash_mod_struct_ops *op;
	int prog_fd;
	u32 moff;

	uop = (const struct hash_mod_struct_ops *)udata;
	op = (struct hash_mod_struct_ops *)kdata;

	moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	/*check function member */
	case offsetof(struct hash_mod_struct_ops, callback):
		goto func_member;
	default:
		return -EINVAL;
	}

func_member:
	prog_fd = (int)(*(unsigned long *)(udata + moff));
	if (!prog_fd) {
		return -EINVAL;
	} else {
		/* It works because the callback is the only function member for now */
		pr_info("hash_mod_struct_ops: got callback fd %d\n", prog_fd);
		callback_prog_fd = prog_fd;
	}

	return 0;
}

static int hash_mod_struct_ops_reg(void *kdata)
{
	return hash_callback_register((struct hash_callback_ops *)kdata,
				      callback_prog_fd);
}

static void hash_mod_struct_ops_unreg(void *kdata)
{
	hash_callback_unregister((struct hash_callback_ops *)kdata);
}

extern const struct bpf_func_proto *
default_mod_stops_get_func_proto(enum bpf_func_id func_id,
				 const struct bpf_prog *prog);

extern bool default_mod_stops_is_valid_access(int off, int size,
					      enum bpf_access_type type,
					      const struct bpf_prog *prog,
					      struct bpf_insn_access_aux *info);

static int hash_mod_stops_btf_struct_access(struct bpf_verifier_log *log,
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

	/* FIXME: Is this correct? */
	end = sizeof(struct hash_mod_struct_ops_ctx);

	if (off + size > end) {
		bpf_log(log,
			"write access at off %d with size %d beyond the size of hash_mod_struct_ops_ctx ended at %zu\n",
			off, size, end);
		return -EACCES;
	}

	return 0;
}

const struct bpf_verifier_ops demo_mod_stops_verifier_ops = {
	.get_func_proto = default_mod_stops_get_func_proto,
	.is_valid_access = default_mod_stops_is_valid_access,
	.btf_struct_access = hash_mod_stops_btf_struct_access,
};

struct bpf_struct_ops bpf_hash_mod_struct_ops = {
	.verifier_ops = &demo_mod_stops_verifier_ops,
	.reg = hash_mod_struct_ops_reg,
	.unreg = hash_mod_struct_ops_unreg,
	.check_member = hash_mod_struct_ops_check_member,
	.init_member = hash_mod_struct_ops_init_member,
	.init = hash_mod_struct_ops_init,
	.name = "hash_mod_struct_ops",
};

BPF_MODULE_STRUCT_OPS_SEC(hash_mod_struct_ops, BPF_MOD_STRUCT_OPS_TYPES);

static int __init hash_mod_struct_ops_module_init(void)
{
	int ret;
	ret = bpf_reg_module_struct_ops(hash_mod_struct_ops);
	if (ret < 0) {
		pr_err("hash_mod_struct_ops: failed to register mod_struct_ops %s\n",
		       THIS_MODULE->name);
		return -1;
	}
	pr_err("hash_mod_struct_ops: register mod_struct_ops %s\n",
	       THIS_MODULE->name);
	return 0;
}

static void __exit hash_mod_struct_ops_module_exit(void)
{
	bpf_unreg_module_struct_ops(hash_mod_struct_ops);
	pr_info("unregister mod_struct_ops %s\n", THIS_MODULE->name);
}

/* Register module functions */
module_init(hash_mod_struct_ops_module_init);
module_exit(hash_mod_struct_ops_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yang Hanlin");
MODULE_DESCRIPTION("Hashing algorithm callback struct ops");
MODULE_VERSION("0.0.1");
