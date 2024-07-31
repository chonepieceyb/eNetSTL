#include <linux/bpf_struct_ops_module.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/bpf_verifier.h>

#include "bpf_ptr_base_ext_ops.h"

extern const struct bpf_func_proto *
default_mod_stops_get_func_proto(enum bpf_func_id func_id,
			   const struct bpf_prog *prog);

extern bool default_mod_stops_is_valid_access(int off, int size, enum bpf_access_type type,
					const struct bpf_prog *prog,
					struct bpf_insn_access_aux *info);

extern int bpf_reg_module_struct_ops(struct bpf_module_struct_ops *mod_struct_ops);
extern int bpf_unreg_module_struct_ops(struct bpf_module_struct_ops *mod_struct_ops);

extern int reg_node_base_ext_ops(struct node_base_ext_ops *new_ext_ops);
extern void unreg_node_base_ext_ops(struct node_base_ext_ops *ops);

#define BPF_MOD_STRUCT_OPS_TYPES(fn)	\
fn(node_base_ext_ops)					\

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

static const struct btf_type *node_base_ctx_type;
static u32 node_base_ctx_id;

static const struct btf_type *node_base_user_config_type;
static u32 node_base_user_config_id;

static const struct btf_type *node_lookup_res_type;
static u32 node_lookup_res_id;

static const struct btf_type *node_common_type;
static u32 node_common_id;

static int node_base_ext_ops_init(struct btf *btf)
{
	node_base_ctx_id = btf_find_by_name_kind(btf, "node_base_ctx", BTF_KIND_STRUCT);
        if (node_base_ctx_id < 0) {
                pr_err("can not find btf type id for node_base_ctx\n");
                return -EINVAL;
        }
        node_base_ctx_type = btf_type_by_id(btf, node_base_ctx_id);

        // 查找 node_base_user_config
        node_base_user_config_id = btf_find_by_name_kind(btf, "node_base_user_config", BTF_KIND_STRUCT);
        if (node_base_user_config_id < 0) {
                pr_err("can not find btf type id for node_base_user_config\n");
                return -EINVAL;
        }
        node_base_user_config_type = btf_type_by_id(btf, node_base_user_config_id);

        // 查找 node_lookup_res
        node_lookup_res_id = btf_find_by_name_kind(btf, "node_lookup_res", BTF_KIND_STRUCT);
        if (node_lookup_res_id < 0) {
                pr_err("can not find btf type id for node_lookup_res\n");
                return -EINVAL;
        }
        node_lookup_res_type = btf_type_by_id(btf, node_lookup_res_id);

        // 查找 node_user_data
        node_common_id = btf_find_by_name_kind(btf, "node_common", BTF_KIND_STRUCT);
        if (node_common_id < 0) {
                pr_err("can not find btf type id for node_common\n");
                return -EINVAL;
        }
        node_common_type = btf_type_by_id(btf, node_common_id);
	return 0;
}
    
static int node_base_ext_ops_check_member(const struct btf_type *t,
				    const struct btf_member *member, const struct bpf_prog *prog)
{
        u32 moff; 
        moff = __btf_member_bit_offset(t, member) / 8;
        switch (moff) {
        case offsetof(struct node_base_ext_ops, user_configure):
	        /* allow to set first_func */
		break;
        case offsetof(struct node_base_ext_ops, lookup):
	        /* allow to set first_func */
		break;
        case offsetof(struct node_base_ext_ops, update):
        /* allow to set first_func */
        break;
        case offsetof(struct node_base_ext_ops, delete):
        /* allow to set first_func */
        break;
        case offsetof(struct node_base_ext_ops, manipulate):
        /* allow to set first_func */
        break;
	default: 
	        return -ENOTSUPP;
        }
	return 0;
}

static int node_base_ext_ops_init_member(const struct btf_type *t,
				   const struct btf_member *member,
				   void *kdata, const void *udata)
{
	const struct node_base_ext_ops *uop;
	struct node_base_ext_ops *op;
	int prog_fd;
	u32 moff;

	uop = (const struct node_base_ext_ops *)udata;
	op = (struct node_base_ext_ops *)kdata;

	moff = __btf_member_bit_offset(t, member) / 8;
	    
	switch (moff) {
        /*check function member */
	case offsetof(struct node_base_ext_ops, user_configure):
		goto func_member;
        case offsetof(struct node_base_ext_ops, lookup):
		goto func_member;
        case offsetof(struct node_base_ext_ops, update):
		goto func_member;
        case offsetof(struct node_base_ext_ops, delete):
		goto func_member;
        case offsetof(struct node_base_ext_ops, manipulate):
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

static int node_base_ext_ops_reg(void *kdata)
{
	return reg_node_base_ext_ops(kdata);
}

static void node_base_ext_ops_unreg(void *kdata) 
{
	unreg_node_base_ext_ops(kdata);
}

static int node_base_ext_ops_btf_struct_access(struct bpf_verifier_log *log,
					const struct bpf_reg_state *reg,
					int off, int size)
{
	const struct btf_type *t;
	size_t end;

	t = btf_type_by_id(reg->btf, reg->btf_id);
        if (t == node_base_ctx_type) {
                if (off >= offsetof(struct node_base_ctx, mctx)) {
                        end = offsetofend(struct node_base_ctx, mctx);
                } else {
                        bpf_log(log, "no write support to node_base_ctx at off %d\n", off);
                        return -EACCES;
                }
        } else if (t == node_base_user_config_type) {
                switch (off) {
                case offsetof(struct node_base_user_config, child_num):
                        end = offsetofend(struct node_base_user_config, child_num);
                        break;
                default:
                        bpf_log(log, "no write support to node_base_user_config at off %d\n", off);
                        return -EACCES;
                }
        } else if (t == node_lookup_res_type) {
                switch (off) {
                case offsetof(struct node_lookup_res, node_idx):
                        end = offsetofend(struct node_lookup_res, node_idx);
                        break;
                default:
                        bpf_log(log, "no write support to node_lookup_res at off %d\n", off);
                        return -EACCES;
                }
        } else if (t == node_common_type) {
                if (off >= offsetof(struct node_common, user_data)) {
                        end = offsetofend(struct node_common, user_data);
                } else {
                        bpf_log(log, "no write support to node_common at off %d\n", off);
                        return -EACCES;
                }
        } else {
                bpf_log(log, "node_base_ext_ops only read is upported");
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


const struct bpf_verifier_ops node_base_ext_ops_verifier_ops = {
	.get_func_proto		= default_mod_stops_get_func_proto,
	.is_valid_access	= default_mod_stops_is_valid_access,
	.btf_struct_access	= node_base_ext_ops_btf_struct_access,
};

struct bpf_struct_ops bpf_node_base_ext_ops = {
	.verifier_ops = &node_base_ext_ops_verifier_ops,
	.reg = node_base_ext_ops_reg,
	.unreg = node_base_ext_ops_unreg,
	.check_member = node_base_ext_ops_check_member,
	.init_member = node_base_ext_ops_init_member,
	.init = node_base_ext_ops_init,
	.name = "node_base_ext_ops",
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