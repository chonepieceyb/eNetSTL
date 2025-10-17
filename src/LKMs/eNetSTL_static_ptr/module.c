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

//b is target
static inline int skip_key_cmp(skip_key_type_t *a, skip_key_type_t *b)
{
	// log_debug("Comparing keys: %u and %u", a->key, b->key);

   
	// if (a->key < b->key) {
	// 	return -1;
	// } else if (a->key > b->key) {
	// 	return 1;
	// } else {
	// 	return 0;	
	// }

	int size = (sizeof(skip_key_type_t) >> 1);
	for (int i = 0; i < size; i++) {
		__u16 *a_ptr = (__u16 *)((__u16*)a + i);
		__u16 *b_ptr = (__u16 *)((__u16*)b + i);
		if (*a_ptr > *b_ptr) {
			return 1;
		} else if (*a_ptr < *b_ptr) {
			return -1;
		} else {
			continue;
		}
	}
	return 0;
}

struct jump_target {
        u64 null_node_idx;  //if  curr_node_idx is null 
        u64 null_off;
        u64 left_node_idx;   // left child node index
        u64 left_off; 
        u64 right_node_idx;  // right child node index
        u64 right_off;

};

static inline int  enetstl_node_route(
        struct eNetSTL_node_container* container, u64 *curr_node_idx, 
        void *target_key, size_t size, struct jump_target *target) 
{
        if (*curr_node_idx == target->null_node_idx) {
                //null node
                if (target->null_off > sizeof(enetstl_node_type) - sizeof(u64)) {
                        return -1; //-1 means error
                }
                enetstl_node_type *next_node = (enetstl_node_type*)__get_batch_idx(target->null_node_idx, container);
                *curr_node_idx = *(u64*)((void*)next_node + target->null_off);
                return 3;
        }

        enetstl_node_type *node = (enetstl_node_type*)__get_batch_idx(*curr_node_idx, container);
        int cmp =  skip_key_cmp((skip_key_type_t*)target_key, &node->key);
        if (cmp == 0) {
                return 0;  //0 means found
        } else if (cmp < 0) {
                //move to left
                //check off 
                u64 left_off = target->left_off;
                if (left_off > sizeof(enetstl_node_type) - sizeof(u64)) {
                        return -1; //-1 means error
                }
                enetstl_node_type *left_node = (enetstl_node_type*)__get_batch_idx(target->left_node_idx, container);
                *curr_node_idx = *(u64*)((void*)left_node + left_off);
                return 1; //1 means goto the left 
        } else {
                //move to right
                //check off 
                u64 right_off = target->right_off;
                if (right_off > sizeof(enetstl_node_type) - sizeof(u64)) {
                        return -1; //-1 means error
                }
                enetstl_node_type *right_node = (enetstl_node_type*)__get_batch_idx(target->right_node_idx, container);
                *curr_node_idx = *(u64*)((void*)right_node + right_off);
                return 2; //2 means goto the right
        }
}


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
        //this method is not safe with use-after-free issue;
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

__bpf_kfunc int bpf_enetstl_node_route(
        struct eNetSTL_container* container, u64 *curr_node_idx, 
        void *target_key__buf, size_t size__sz, struct jump_target *target) 
{
        return enetstl_node_route((struct eNetSTL_node_container*)container, curr_node_idx, target_key__buf, size__sz, target);
}

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
BTF_ID_FLAGS(func, bpf_enetstl_node_route, KF_TRUSTED_ARGS)
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