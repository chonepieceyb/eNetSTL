#include <linux/export.h>
#include <linux/preempt.h>
#include <linux/bitops.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>
#include <linux/filter.h>

#include "nn_inference.h"



__bpf_kfunc_start_defs();


__bpf_kfunc int bpf_enetstl_write_node(enetstl_node_type *node, size_t off, void *data__buf, size_t size__sz)
{	
        if (unlikely(off + size__sz > sizeof(*node)))
                return -1;
        memcpy((void*)node + off, data__buf, size__sz);
        return 0;
}
__bpf_kfunc_end_defs();


/* BTF kfunc ID set and registration */
//BTF_SET8_START(enetstl_static_ptr_kfunc_ids)
BTF_KFUNCS_START(nn_ids_kfuncs)
BTF_ID_FLAGS(func, bpf_enetstl_write_node)
//BTF_SET8_END(enetstl_static_ptr_kfunc_ids)
BTF_KFUNCS_END(nn_ids_kfuncs)

static const struct btf_kfunc_id_set nn_ids_kfunc_set = {
        .owner = THIS_MODULE,
        .set   = &nn_ids_kfuncs,
};

static int __init nn_ids_init(void)
{
        ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &nn_ids_kfunc_set);
        if (ret < 0) {
                pr_err("failed to register nn_ids kfunc set\n");
                goto err;
        }
        pr_info("register nn_ids kfunc set");
        return 0;
}

static void __exit nn_ids_exit(void)
{
        pr_info("nn_ids exit");
}

/* Register module functions */
module_init(nn_ids_init);
module_exit(nn_ids_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bin Yang");
MODULE_DESCRIPTION("NN IDS LKM implementation");
MODULE_VERSION("0.0.1");