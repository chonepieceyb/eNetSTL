#include "linux/preempt.h"
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>
#include <linux/bpf_mem_alloc.h>

extern int register_btf_kfunc_id_set(enum bpf_prog_type prog_type, const struct btf_kfunc_id_set *kset);
extern void bpf_map_area_free(void *area);
extern void *bpf_map_area_alloc(u64 size, int numa_node);

#define OWN_BY_BPF -1

static struct bpf_mem_alloc percpu_global_ma;

/*data of 16 byters*/
struct node_2_16_data {
	char data[16];
};

struct node_2_16 {
	/*two child*/
	struct node_2_16 *ptrs[2];
	struct node_2_16 *onwer;
	int refcnt;
	/*data 16 byte*/
	struct node_2_16_data data;
};

__bpf_kfunc u32 test_func(u32 data) 
{
	return 0;
} 
EXPORT_SYMBOL_GPL(test_func);

__bpf_kfunc struct node_2_16_data* node_2_16_new(void) 
{
	/* should set zero*/
	struct node_2_16 *node = bpf_mem_cache_alloc(&percpu_global_ma);
	if (unlikely(node == NULL))
		return NULL; 
	memset(&node->ptrs, 0, sizeof(node->ptrs));
	node->onwer = ERR_PTR(OWN_BY_BPF);
	node->refcnt = 1;
	/*return only data*/
	return &node->data;
}
EXPORT_SYMBOL_GPL(node_2_16_new);

static void __node_2_16_destory(struct node_2_16 *node) {
	pr_debug("try to release node[%u], %p, ref: %d, onwer %lld, child0 %p, child1 %p", *(u32*)&(node->data), node, node->refcnt, *(s64*)&node->onwer, node->ptrs[0], node->ptrs[1]);
	int i; 
	for (i = 0; i < 2; i++) {
		struct node_2_16 *child = node->ptrs[i];
		if (child == NULL) 
			continue;
		if (child->onwer != node) 
			continue;
 		/* recursively release*/
		__node_2_16_destory(child);
	}
	node->refcnt -=1;
	if (node->refcnt <= 0) {
		pr_debug("release node[%u], %p", *(u32*)&(node->data), node);
		bpf_mem_cache_free(&percpu_global_ma, node);
	}
}

/*release this node and linked node, onwer should be eBPF*/
__bpf_kfunc void node_2_16_release(struct node_2_16_data* p) 
{
	struct node_2_16 *node = container_of(p, struct node_2_16, data);
	if (node->onwer == ERR_PTR(OWN_BY_BPF)) {
		preempt_disable();
		__node_2_16_destory(node);
		preempt_enable();
	} else {
		/* onwer is other pointer, release child: ref->1 (from ptr to BPF)*/
		node->refcnt -= 1;
		if (node->refcnt == 0)
			bpf_mem_cache_free(&percpu_global_ma, node);
	}
	
}
EXPORT_SYMBOL_GPL(node_2_16_release);

/*iterate, get for read and write data*/
__bpf_kfunc struct node_2_16_data* node_2_16_get_child(struct node_2_16_data *parent, u32 idx) 
{
	struct node_2_16 *node = container_of(parent, struct node_2_16, data);
	if (unlikely(idx >= 2)) 
		return NULL; 
	if (node->ptrs[idx] == NULL) {
		return NULL;
	}
	struct node_2_16 *cnode = node->ptrs[idx];
	cnode->refcnt += 1; 
	return &cnode->data;
}
EXPORT_SYMBOL_GPL(node_2_16_get_child);

__bpf_kfunc int node_2_16_child_equal(struct node_2_16_data *parent, int idx, struct node_2_16_data *child)
{
	struct node_2_16 *node_p = container_of(parent, struct node_2_16, data);
	struct node_2_16 *node_c = container_of(child, struct node_2_16, data);
	if (unlikely(idx >= 2)) 
		return -1;
	return node_p->ptrs[idx] == node_c;
}
EXPORT_SYMBOL_GPL(node_2_16_child_equal);

__bpf_kfunc int node_2_16_childs_equal(struct node_2_16_data *p1, int idx1, struct node_2_16_data *p2, int idx2)
{
	struct node_2_16 *node1 = container_of(p1, struct node_2_16, data);
	struct node_2_16 *node2 = container_of(p2, struct node_2_16, data);
	if (unlikely(idx1 >= 2 || idx2 >= 2)) 
		return -1;
	return node1->ptrs[idx1] == node2->ptrs[idx2];
}
EXPORT_SYMBOL_GPL(node_2_16_childs_equal);

/*set the onwer of the node, after set onwer, release should be called*/
__bpf_kfunc int node_2_16_set_onwer(struct node_2_16_data *parent, struct node_2_16_data *child, u32 idx) 
{	
	struct node_2_16 *node_p = container_of(parent, struct node_2_16, data);
	struct node_2_16 *node_c = container_of(child, struct node_2_16, data);
	BUG_ON(node_c->onwer != ERR_PTR(OWN_BY_BPF));
	if (unlikely(idx >= 2)) {
		return -1;
	}
	/* transfer onwership*/
	node_c->onwer = node_p;
	node_p->ptrs[idx] = node_c;
	node_c->refcnt += 1;
	return 0; 
}
EXPORT_SYMBOL_GPL(node_2_16_set_onwer);

/*delete 'idx' child of parent, 'ACQUIRE' the child memship , parent should be the onwer of 'idx' child*/
__bpf_kfunc struct node_2_16_data* node_2_16_release_child(struct node_2_16_data *parent, u32 idx) 
{
	struct node_2_16 *node_p = container_of(parent, struct node_2_16, data);
	struct node_2_16 *child;
	if (unlikely(idx >= 2)) {
		return NULL;
	}
	child = node_p->ptrs[idx];
	if (unlikely(child->onwer != node_p)) 
		return NULL;
	node_p->ptrs[idx] = NULL;
	child->onwer = ERR_PTR(OWN_BY_BPF);
	return &child->data;
}
EXPORT_SYMBOL_GPL(node_2_16_release_child);

__bpf_kfunc int node_2_16_write(struct node_2_16_data *parent, size_t off, void *data__buf, size_t size__sz)
{
	if (unlikely(off + size__sz >= 16) )
		return -1;
	memcpy(&parent->data + off, data__buf, size__sz);
	return 0;
}
EXPORT_SYMBOL_GPL(node_2_16_write);


BTF_SET8_START(bpf_ptr_structure_kfunc_ids)
BTF_ID_FLAGS(func, test_func)
BTF_ID_FLAGS(func, node_2_16_new, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, node_2_16_release, KF_RELEASE)
BTF_ID_FLAGS(func, node_2_16_get_child, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, node_2_16_set_onwer)
BTF_ID_FLAGS(func, node_2_16_release_child, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, node_2_16_write)
BTF_SET8_END(bpf_ptr_structure_kfunc_ids)

BTF_ID_LIST(ptr_structure_dtor_ids)
BTF_ID(struct, node_2_16_data)
BTF_ID(func, node_2_16_release)

static const struct btf_kfunc_id_set bpf_ptr_structure_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &bpf_ptr_structure_kfunc_ids,
};

static int __init networking_pointer_structure_init(void) {
        int ret;
	preempt_disable();
	ret = bpf_mem_alloc_init(&percpu_global_ma, sizeof(struct node_2_16), true);
	preempt_enable();
	if (ret) {
		pr_err("failed to init bpf mem alloc");
		return ret;
	}
	const struct btf_id_dtor_kfunc ptr_structure_dtors[] = {
		{
			.btf_id       = ptr_structure_dtor_ids[0],
			.kfunc_btf_id = ptr_structure_dtor_ids[1]
		}
	};

	ret = ret ?: register_btf_id_dtor_kfuncs(ptr_structure_dtors,
						  ARRAY_SIZE(ptr_structure_dtors),
						  THIS_MODULE);
        ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &bpf_ptr_structure_kfunc_set);
	if (ret < 0) {
		pr_err("failed to reigster networking DP ALG kfunc set\n");
		goto err;
	}
        pr_info("register networking DP ALG set");
	return 0;
err:
	bpf_mem_alloc_destroy(&percpu_global_ma);
	return ret;
}

static void __exit networking_pointer_structure_exit(void) {
	preempt_disable();
	bpf_mem_alloc_destroy(&percpu_global_ma);
	preempt_enable();
	pr_info("unregister networking DP ALG set");
}

/* Register module functions */
module_init(networking_pointer_structure_init);
module_exit(networking_pointer_structure_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chonepieceyb");
MODULE_DESCRIPTION("BPF networking datapath pointer-based data structrue sets");
MODULE_VERSION("0.01");