#include "linux/cache.h"
#include "linux/compiler.h"
#include "linux/list.h"
#include "linux/preempt.h"
#include "linux/stddef.h"
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>
#include <linux/bpf_mem_alloc.h>
#include <linux/bitops.h>

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


#define NODE_SIZE 512

/*pointer structure lib-new*/

static struct bpf_mem_alloc percpu_container_ma;
static struct bpf_mem_alloc percpu_ptr_ma;

#define MAX_TMP_NUM 32



#define PTR_SIZE 16
#define IN_NUM PTR_SIZE
#define OUT_NUM PTR_SIZE
#define DATA_SIZE1 52
#define DATA_SIZE2 160
// struct __node_common {
// /* u32 size;
// *  int ref_cnt;
// *  out[child_num];
// *  in[parent_num];
// *  
// * 
// */
// 	u32 in_num; 
// 	u32 out_num;
// 	int refcnt;
// 	u32 data_off;
// 	struct ptr_node_container *owner; 
// 	unsigned long in_map;
// 	unsigned long out_map;
// 	struct list_head node;
// 	DECLARE_FLEX_ARRAY(struct __node_common*, ptrs);
// };

struct __node_common {
	struct ptr_node_container *owner;
	int refcnt;
	char data1[DATA_SIZE1];
	struct __node_common *outs[PTR_SIZE];
	struct __node_common *ins[PTR_SIZE];
	unsigned long in_map;
	unsigned long out_map;
	struct list_head node;
	char data2[DATA_SIZE2];
}____cacheline_aligned_in_smp;

typedef struct __node_common ptr_node; 

struct ptr_node_container {
	struct list_head node_list;
	//u32 tmp_num;
	ptr_node* tmps[MAX_TMP_NUM];
	//DECLARE_FLEX_ARRAY(ptr_node*, tmps);
};

#define MAX_PTRS 42

struct ptr_node_container*  ptr_create_node_container(u32 tmp_num) 
{
	//struct ptr_node_container *c = bpf_mem_alloc(&percpu_container_ma, sizeof(struct ptr_node_container) + tmp_num * sizeof(void*));
	preempt_disable();
	struct ptr_node_container *c = bpf_mem_cache_alloc(&percpu_container_ma);
	preempt_enable();
	if (c == NULL) {
		return NULL;
	}
	//c->tmp_num = tmp_num;
	INIT_LIST_HEAD(&c->node_list);
	for (int i = 0; i < MAX_TMP_NUM; i++) {
		c->tmps[i] = NULL;
	}
	pr_debug("ptr_create_node_container %p", c);
	return c;
}
EXPORT_SYMBOL_GPL(ptr_create_node_container);

void ptr_destory_node_container(struct ptr_node_container *c)
{
	pr_debug("ptr_destory_node_container");
	struct __node_common *entry, *n;
	list_for_each_entry_safe(entry, n,  &c->node_list, node) {
		//check refcnt 
		pr_debug("contaiiner release node %p, refcnt %d", entry, entry->refcnt);
		list_del(&entry->node);   /*del from link list*/
		if (--entry->refcnt == 0)   /* --refcnt*/ {
			preempt_disable();
			bpf_mem_cache_free(&percpu_ptr_ma, entry);
			preempt_enable();
		}
		pr_debug("contaiiner success release node");
	}
	pr_debug("contaiiner free %p", c);
	preempt_disable();
	bpf_mem_cache_free(&percpu_container_ma, c);
	preempt_enable();
}
EXPORT_SYMBOL_GPL(ptr_destory_node_container);

/*only can set onwership belongs to c*/
void ptr_container_set_tmp(struct ptr_node_container* c, ptr_node *node, u32 idx) 
{
	//if (unlikely(idx > c->tmp_num))
	if (unlikely(idx >= MAX_TMP_NUM))
		return;
	struct __node_common *n  = (struct __node_common *)(node);
	if (unlikely(n->owner != c))
		return;
	c->tmps[idx] = node;
	return;
}
EXPORT_SYMBOL_GPL(ptr_container_set_tmp);

ptr_node* ptr_container_get_tmp(struct ptr_node_container* c, u32 idx) 
{
	//if (unlikely(idx > c->tmp_num))ptr_container_get_tmp
	// if (unlikely(idx >= MAX_TMP_NUM))
	// 	return NULL;
	struct __node_common *n =  (struct __node_common *)(c->tmps[idx & (MAX_TMP_NUM - 1)]);
	if (likely(n != NULL)) {
		n->refcnt++;
		return (ptr_node*)n;
	} else {
		return NULL;
	}
}
EXPORT_SYMBOL_GPL(ptr_container_get_tmp);

ptr_node* ptr_alloc_node(void) 
{
	preempt_disable();
	struct __node_common *__node = (struct __node_common *)bpf_mem_cache_alloc(&percpu_ptr_ma);
	preempt_enable();
	if (unlikely(__node == NULL)) {
		return NULL; 
	}
	pr_debug("node alloc size %lu", sizeof(ptr_node));
	memset(__node, 0, sizeof(ptr_node));
	__node->refcnt = 1;  /*set ref_cnt*/
	__node->owner = NULL;
	/* add to node list*/
	//list_add( &__node->node, &c->node_list);  /*delete in release*/
	return (ptr_node*)__node;
}
EXPORT_SYMBOL_GPL(ptr_alloc_node);

void ptr_set_owner(struct ptr_node_container *c, ptr_node *node) {
	struct __node_common *__node  = (struct __node_common *)(node);
	if (unlikely(__node->owner != NULL))
		return;
	list_add( &__node->node, &c->node_list);  /*delete in clear owner*/
	__node->owner = c;   /*set owner add refcnt*/
	__node->refcnt += 1; 
	return ;
}
EXPORT_SYMBOL_GPL(ptr_set_owner);

void ptr_unset_owner(ptr_node *node) {
	struct __node_common *__node  = (struct __node_common *)(node);
	struct __node_common *__pre_node, *__next_node;
	int i, j;
	u32 in_num = IN_NUM, out_num = OUT_NUM;
	if (unlikely(__node->owner == NULL))
		return; 
	/* invalid all referenced ptrs*/
	if (unlikely(__node->out_map != 0)) {
		/* invalid all ptr2 in equals ptr1 ,it is likely that use have done this through unconnect*/
		for (i = 0; i < out_num; i++) {
			__next_node = __node->outs[i];
			pr_debug("try invald out node %p, out %d", __next_node, i);
			if (__next_node == NULL) 
				continue; 
			for (j = 0; j < IN_NUM; j++) {
				pr_debug("try in ptr %d", j);
				if (__next_node->ins[j] == __node) {
					pr_debug("invald in ptr %p %d", __next_node->ins[j], j);
					__next_node->ins[j] = NULL;
				}
			}
		}
	}
	if (unlikely(__node->in_map != 0)) {
		/* invalid all ptr1, it is likely that use have done this through unconnect*/
		for (i = 0; i < in_num; i++) {
			__pre_node = __node->ins[i];
			pr_debug("try invald in node %p, in %d", __pre_node, i);
			if (__pre_node == NULL) 
				continue;
			for (j = 0; j < OUT_NUM; j++) {
				pr_debug("try invalid out ptr %d", j);
				if (__pre_node->outs[j] == __node) {
					pr_debug("invald out ptr %p %d", __pre_node->outs[j], j);
					__pre_node->outs[j] = NULL;
				}
			}
		}
	}
	/*delete from node_list*/
	list_del(&__node->node);
	__node->owner = NULL;
	/*refcnt >= 2 here*/
	__node->refcnt--;
	return;
}
EXPORT_SYMBOL_GPL(ptr_unset_owner);

/*pointer wrapper*/
ptr_node* ptr_get_out(ptr_node *parent, u32 idx)
{
	struct __node_common *__node = (struct __node_common *)parent;
	// if (unlikely(idx >= OUT_NUM)) {
	// 	return NULL;
	// }
	struct __node_common *__node_get = __node->outs[idx & (OUT_NUM - 1)];
	if (__node_get == NULL) 
		return NULL;
	__node_get->refcnt++;
	pr_debug("get %p out %d %p, refcnt %d", parent, idx, __node_get, __node_get->refcnt);
	return (ptr_node*)(__node_get);
}
EXPORT_SYMBOL_GPL(ptr_get_out);

void ptr_release_node(ptr_node *ptr)
{
	struct __node_common *__node = (struct __node_common *)ptr;
	pr_debug("ptr_release_node %p refcnt %d", ptr, __node->refcnt);
	if (unlikely((--__node->refcnt) == 0)) {
		preempt_disable();
		bpf_mem_cache_free(&percpu_ptr_ma, __node);
		preempt_enable();
	}
}
EXPORT_SYMBOL_GPL(ptr_release_node);

int ptr_connect(ptr_node *p1, u32 idx1, ptr_node *p2, u32 idx2)
{
	/*p1->p2
	 *out, in
	 *direct set ptr it is not our responsabioity to ensure user alg is correct*/
	struct __node_common *__p1 = (struct __node_common*)(p1);
	struct __node_common *__p2 = (struct __node_common*)(p2);
	if (unlikely(__p1->owner != __p2->owner  || __p1->owner  == NULL))
		return -EINVAL;
	if (unlikely(idx1 >= OUT_NUM || idx2 >= IN_NUM)) {
		return -EINVAL;
	}
	struct __node_common **__pp1_out =  &(__p1->outs[idx1]);  
	struct __node_common **__pp2_in = &(__p2->ins[idx2]); 
	if (unlikely(*__pp1_out != NULL || *__pp2_in != NULL)) {
		return -1;
	}
	*__pp1_out = __p2;
	__set_bit(idx1, &__p1->out_map);
	*__pp2_in = __p1;
	__set_bit(idx2, &__p2->in_map);
	return 0;
}
EXPORT_SYMBOL_GPL(ptr_connect);

int ptr_unconnect(ptr_node *p1, u32 idx1, ptr_node *p2, u32 idx2)
{
	struct __node_common *__p1 = (struct __node_common*)(p1);
	struct __node_common *__p2 = (struct __node_common*)(p2);
	if (unlikely(__p1->owner != __p2->owner || __p1->owner  == NULL))
		return -EINVAL;
	if (unlikely(idx1 >= OUT_NUM || idx2 >= IN_NUM)) {
		return -EINVAL;
	}
	struct __node_common **__pp1_out =  &__p1->outs[idx1];  
	struct __node_common **__pp2_in =  &__p2->ins[idx2];
	if (unlikely(*__pp1_out !=  __p2 || *__pp2_in != __p1)) {
		return -1;
	}
	*(void**)__pp1_out = NULL;
	__clear_bit(idx1, &__p1->out_map);
	*(void**)__pp2_in = NULL;
	__clear_bit(idx2, &__p2->in_map);
	return 0;
}
EXPORT_SYMBOL_GPL(ptr_unconnect);

__bpf_kfunc int ptr_write_data1(ptr_node *node, size_t off, void *data__buf, size_t size__sz)
{	
	pr_debug("ptr_write node %p, off %lu, size %lu", node, off, size__sz);
	struct __node_common *__node = (struct __node_common *)node;
	if (unlikely(off < offsetof(ptr_node, data1) || off + size__sz > (offsetof(ptr_node, data1) + DATA_SIZE1)))
		return -1;
	memcpy((void*)__node + off, data__buf, size__sz);
	return 0;
}
EXPORT_SYMBOL_GPL(ptr_write_data1);

__bpf_kfunc int ptr_write_data2(ptr_node *node, size_t off, void *data__buf, size_t size__sz)
{	
	pr_debug("ptr_write node %p, off %lu, size %lu", node, off, size__sz);
	struct __node_common *__node = (struct __node_common *)node;
	if (unlikely(off < offsetof(ptr_node, data2) || off + size__sz > (offsetof(ptr_node, data2) + DATA_SIZE2)))
		return -1;
	memcpy((void*)__node + off, data__buf, size__sz);
	return 0;
}
EXPORT_SYMBOL_GPL(ptr_write_data2);


BTF_SET8_START(bpf_ptr_structure_kfunc_ids)
BTF_ID_FLAGS(func, test_func)
BTF_ID_FLAGS(func, node_2_16_new, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, node_2_16_release, KF_RELEASE)
BTF_ID_FLAGS(func, node_2_16_get_child, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, node_2_16_set_onwer)
BTF_ID_FLAGS(func, node_2_16_release_child, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, node_2_16_write)
BTF_ID_FLAGS(func, ptr_create_node_container, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, ptr_destory_node_container, KF_RELEASE)
BTF_ID_FLAGS(func, ptr_alloc_node, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, ptr_release_node, KF_RELEASE)
BTF_ID_FLAGS(func, ptr_set_owner)
BTF_ID_FLAGS(func, ptr_unset_owner)
BTF_ID_FLAGS(func, ptr_container_set_tmp)
BTF_ID_FLAGS(func, ptr_container_get_tmp, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, ptr_connect)
BTF_ID_FLAGS(func, ptr_unconnect)
BTF_ID_FLAGS(func, ptr_get_out, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, ptr_write_data1)
BTF_ID_FLAGS(func, ptr_write_data2)
BTF_SET8_END(bpf_ptr_structure_kfunc_ids)

BTF_ID_LIST(ptr_structure_dtor_ids)
BTF_ID(struct, node_2_16_data)
BTF_ID(func, node_2_16_release)
BTF_ID(struct, ptr_node_container)
BTF_ID(func, ptr_destory_node_container)
BTF_ID(struct, __node_common)
BTF_ID(func, ptr_release_node)

static const struct btf_kfunc_id_set bpf_ptr_structure_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &bpf_ptr_structure_kfunc_ids,
};

static int init_mem_allocs(void)
{
	int ret;
	ret = bpf_mem_alloc_init(&percpu_global_ma, sizeof(struct node_2_16), false);
	if (ret) {
		pr_err("percpu_global_ma init fail ret %d", ret);
		goto fail;
	}
	ret = bpf_mem_alloc_init(&percpu_container_ma, sizeof(struct ptr_node_container), false);
	if (ret) {
		pr_err("percpu_container_ma init fail ret %d", ret);
		goto destory_global;
	}
	ret = bpf_mem_alloc_init(&percpu_ptr_ma, sizeof(ptr_node), false);
	if (ret) {
		pr_err("percpu_ptr_ma init fail ret %d", ret);
		goto destory_container;
	}
	return 0;
destory_container:
	bpf_mem_alloc_destroy(&percpu_container_ma);
destory_global:
	bpf_mem_alloc_destroy(&percpu_global_ma);
fail:	
	return -1; 
}

static void destory_mem_allocs(void)
{
	bpf_mem_alloc_destroy(&percpu_ptr_ma);
	bpf_mem_alloc_destroy(&percpu_container_ma);
	bpf_mem_alloc_destroy(&percpu_global_ma);
}

static int __init networking_pointer_structure_init(void) {
        int ret;
	preempt_disable();
	ret = init_mem_allocs();
	preempt_enable();
	if (ret) {
		pr_err("failed to init bpf mem alloc");
		return ret;
	}
	const struct btf_id_dtor_kfunc ptr_structure_dtors[] = {
		{
			.btf_id       = ptr_structure_dtor_ids[0],
			.kfunc_btf_id = ptr_structure_dtor_ids[1]
		},
		{
			.btf_id       = ptr_structure_dtor_ids[2],
			.kfunc_btf_id = ptr_structure_dtor_ids[3]
		},
		{
			.btf_id       = ptr_structure_dtor_ids[4],
			.kfunc_btf_id = ptr_structure_dtor_ids[5]
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
	preempt_disable();
	destory_mem_allocs();
	preempt_enable();
	return ret;
}

static void __exit networking_pointer_structure_exit(void) {
	preempt_disable();
	destory_mem_allocs();
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