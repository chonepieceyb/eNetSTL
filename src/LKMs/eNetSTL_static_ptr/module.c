#include <linux/export.h>
#include <linux/preempt.h>
#include <linux/bitops.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>
#include <linux/filter.h>

#include "bpf_memalloc.h"
#include "bpf_static_ptr.h"
#include "linux/bpf.h"

__bpf_kfunc_start_defs();

/* BPF kfunc wrappers */
__bpf_kfunc struct eNetSTL_proxy* bpf_enetstl_create_node_proxy(void)
{
        return (struct eNetSTL_proxy*)enetstl_create_node_proxy();
}
//EXPORT_SYMBOL_GPL(bpf_enetstl_create_node_proxy);

__bpf_kfunc struct eNetSTL_container* bpf_enetstl_get_nodes(int fd)
{
        return (struct eNetSTL_container*)enetstl_get_nodes(fd);
}
//EXPORT_SYMBOL_GPL(bpf_enetstl_get_nodes);

__bpf_kfunc enetstl_node_type* bpf_enetstl_get_node(struct eNetSTL_container* container, u64 idx)
{
        return (enetstl_node_type*)__get_batch_idx(idx, (struct eNetSTL_node_container*)container);
}
//EXPORT_SYMBOL_GPL(bpf_enetstl_get_node);

__bpf_kfunc void bpf_enetstl_put_nodes(struct eNetSTL_container* container)
{
        enetstl_put_nodes((struct eNetSTL_node_container*)container);
}
//EXPORT_SYMBOL_GPL(bpf_enetstl_put_nodes);

__bpf_kfunc enetstl_node_type* bpf_enetstl_alloc_node(struct eNetSTL_container* container, u64 *idx)
{
        return (enetstl_node_type*) enetstl_alloc_node((struct eNetSTL_node_container*)container, idx);
}
//EXPORT_SYMBOL_GPL(bpf_enetstl_alloc_node);

__bpf_kfunc void bpf_enetstl_free_node(struct eNetSTL_container* container, u64 idx)
{
        enetstl_free_node((struct eNetSTL_node_container*)container, idx);
}
//EXPORT_SYMBOL_GPL(bpf_enetstl_free_node);

__bpf_kfunc void bpf_enetstl_enlarge_capacity(struct eNetSTL_container* container)
{
        enetstl_enlarge_capacity((struct eNetSTL_node_container*)container);
}
//EXPORT_SYMBOL_GPL(bpf_enetstl_enlarge_capacity);

__bpf_kfunc int bpf_enetstl_write_node(enetstl_node_type *node, size_t off, void *data__buf, size_t size__sz)
{	
        if (unlikely(off + size__sz > sizeof(*node)))
                return -1;
        memcpy((void*)node + off, data__buf, size__sz);
        return 0;
}
//EXPORT_SYMBOL_GPL(bpf_enetstl_write_node);

//in som cases the stupid verifier cannot prove that the read is safe, so we provide a read function
__bpf_kfunc int bpf_enetstl_read_node(enetstl_node_type *node, size_t off, void *data__buf, size_t size__sz)
{	
        if (unlikely(off + size__sz > sizeof(*node)))
                return -1;
        memcpy(data__buf, (void*)node + off, size__sz);
        return 0;
}
//EXPORT_SYMBOL_GPL(bpf_enetstl_read_node);

__bpf_kfunc void bpf_enetstl_destroy_node_proxy(struct eNetSTL_proxy* proxy) {
        enetstl_destroy_node_proxy((struct eNetSTL_node_proxy*)proxy);
}
//EXPORT_SYMBOL_GPL(bpf_enetstl_destroy_node_proxy);
__bpf_kfunc_end_defs();


/* BTF kfunc ID set and registration */
//BTF_SET8_START(enetstl_static_ptr_kfunc_ids)
BTF_KFUNCS_START(enetstl_static_ptr_kfuncs)
BTF_ID_FLAGS(func, bpf_enetstl_create_node_proxy, KF_ACQUIRE | KF_RET_NULL | KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_enetstl_get_nodes, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_enetstl_put_nodes, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_enetstl_alloc_node, KF_TRUSTED_ARGS | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_enetstl_free_node, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_enetstl_get_node, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_enetstl_write_node)
BTF_ID_FLAGS(func, bpf_enetstl_read_node)
BTF_ID_FLAGS(func, bpf_enetstl_enlarge_capacity, KF_RELEASE | KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_enetstl_destroy_node_proxy, KF_RELEASE)
//BTF_SET8_END(enetstl_static_ptr_kfunc_ids)
BTF_KFUNCS_END(enetstl_static_ptr_kfuncs)

static const struct btf_kfunc_id_set enetstl_static_ptr_kfunc_set = {
        .owner = THIS_MODULE,
        .set   = &enetstl_static_ptr_kfuncs,
};

BTF_ID_LIST(eNetSTL_static_ptr_dtor_ids)
BTF_ID(struct, eNetSTL_proxy)
BTF_ID(func, bpf_enetstl_destroy_node_proxy)


static int __init eNetSTL_static_ptr_init(void)
{
        bpf_mem_cache_adjust_size();
	int ret = 0;
        ret = node_proxys_init();
        if (ret) {
                pr_err("failed to init eNetSTL node proxy\n");
                return ret;
        }
	const struct btf_id_dtor_kfunc eNetSTL_static_ptr_kfunc_dtors[] = {
		{
			.btf_id = eNetSTL_static_ptr_dtor_ids[0],
			.kfunc_btf_id = eNetSTL_static_ptr_dtor_ids[1],
		},
	};

	ret = ret ?: register_btf_id_dtor_kfuncs(eNetSTL_static_ptr_kfunc_dtors,
						  ARRAY_SIZE(eNetSTL_static_ptr_kfunc_dtors),
						  THIS_MODULE);
        ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &enetstl_static_ptr_kfunc_set);
        ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &enetstl_static_ptr_kfunc_set);

        if (ret < 0) {
                pr_err("failed to register eNetSTL static kfunc set\n");
                goto err;
        }
        pr_info("register eNetSTL static kfunc set");
        return 0;
err:
        node_proxys_exit();
        return ret;
}

static void __exit eNetSTL_static_ptr_exit(void)
{
        node_proxys_exit();
        pr_info("eNetSTL static ptr exit");
}

/* Register module functions */
module_init(eNetSTL_static_ptr_init);
module_exit(eNetSTL_static_ptr_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bin Yang");
MODULE_DESCRIPTION("eNetSTL Static Ptr Library");
MODULE_VERSION("0.0.1");