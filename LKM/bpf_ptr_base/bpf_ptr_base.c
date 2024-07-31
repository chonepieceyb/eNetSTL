#include "linux/err.h"
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>
#include <linux/bpf_mem_alloc.h>
#include <linux/bitops.h>
#include <linux/hashtable.h>
#include <linux/xxhash.h>

#include "bpf_ptr_base_ext_ops.h"

// extern int bpf_register_custom_map(struct bpf_custom_map_ops *cmap);
// extern void bpf_unregister_custom_map(struct bpf_custom_map_ops *cmap);
extern int bpf_register_static_cmap(struct bpf_map_ops *map, struct module *onwer);
extern void bpf_unregister_static_cmap(struct module *onwer);
extern void bpf_map_area_free(void *area);
extern void *bpf_map_area_alloc(u64 size, int numa_node);

struct node_base_percpu_fields {
	struct node_common *proot;
	struct list_head node_list;
	u32 node_num; 
	struct bpf_mem_alloc node_ma;   //alloc nodes pool
	struct node_base_meta meta;  //node meta
	DECLARE_HASHTABLE(hash_elements, NODE_BASE_HASH_BITS);  //all hash elements is handling in node_list
};

struct node_base_map {
	struct bpf_map map;
	struct node_base_percpu_fields __percpu *percpu_fields;
	u32 child_num;
	u32 key_off;
	u32 value_off; 
	u32 total_size; 
};

static struct node_base_ext_ops *bpf_ops = NULL;
static DEFINE_SPINLOCK(static_ops_lock);

/*hooks for eBPF programs*/
static void default_user_configure(struct node_base_user_config *config) {
	config->child_num = 0;
	//config->data_size = 0;
}

DEFINE_STATIC_CALL_NULL(__static_user_configure, default_user_configure);

static void static_user_configure(struct node_base_user_config *config) 
{
	static_call(__static_user_configure)(config);
}

//init meta
static void default_init_meta(struct node_base_meta *meta) {
	memset(meta, 0, sizeof(*meta));
}

DEFINE_STATIC_CALL_NULL(__static_init_meta, default_init_meta);

static void static_init_meta(struct node_base_meta *meta) 
{
	static_call(__static_init_meta)(meta);
}

//lookup
static int default_lookup(struct node_base_ctx *ctx, struct node_base_meta *meta, struct node_lookup_res *res) {
	return -1;
}

DEFINE_STATIC_CALL_RET0(__static_lookup, default_lookup);

static int static_lookup(struct node_base_ctx *ctx, struct node_base_meta *meta, struct node_lookup_res *res) 
{
	return static_call(__static_lookup)(ctx, meta, res);
}
//update
static int default_update(struct node_base_ctx *ctx, struct node_base_meta *meta) {
	return -1;
}

DEFINE_STATIC_CALL_RET0(__static_update, default_update);

static int static_update(struct node_base_ctx *ctx, struct node_base_meta *meta) 
{
	return static_call(__static_update)(ctx, meta);
}
//delete
static int default_delete(struct node_base_ctx *ctx, struct node_base_meta *meta) {
	return -1;
}

DEFINE_STATIC_CALL_RET0(__static_delete, default_delete);

static int static_delete(struct node_base_ctx *ctx, struct node_base_meta *meta) 
{
	return static_call(__static_delete)(ctx, meta);
}

//manipulate node
static void default_manipulate(struct node_base_ctx *ctx, struct node_common *node) 
{
}

DEFINE_STATIC_CALL_NULL(__static_manipulate, default_manipulate);

static void static_manipulate(struct node_base_ctx *ctx, struct node_common *node) 
{
	static_call(__static_manipulate)(ctx, node);
}

// static_manipulate_1_1
static void default_manipulate_1_1(struct node_base_ctx *ctx, struct node_common *node)
{
}

DEFINE_STATIC_CALL_NULL(__static_manipulate_1_1, default_manipulate_1_1);

static void static_manipulate_1_1(struct node_base_ctx *ctx, struct node_common *node)
{
	static_call(__static_manipulate_1_1)(ctx, node);
}

// static_manipulate_1_2
static void default_manipulate_1_2(struct node_base_ctx *ctx, struct node_common *node)
{
}

DEFINE_STATIC_CALL_NULL(__static_manipulate_1_2, default_manipulate_1_2);

static void static_manipulate_1_2(struct node_base_ctx *ctx, struct node_common *node)
{
	static_call(__static_manipulate_1_2)(ctx, node);
}

// static_manipulate_1_3
static void default_manipulate_1_3(struct node_base_ctx *ctx, struct node_common *node)
{
}

DEFINE_STATIC_CALL_NULL(__static_manipulate_1_3, default_manipulate_1_3);

static void static_manipulate_1_3(struct node_base_ctx *ctx, struct node_common *node)
{
	static_call(__static_manipulate_1_3)(ctx, node);
}

// static_manipulate_1_4
static void default_manipulate_1_4(struct node_base_ctx *ctx, struct node_common *node)
{
}

DEFINE_STATIC_CALL_NULL(__static_manipulate_1_4, default_manipulate_1_4);

static void static_manipulate_1_4(struct node_base_ctx *ctx, struct node_common *node)
{
	static_call(__static_manipulate_1_4)(ctx, node);
}

// static_manipulate_2_1
static void default_manipulate_2_1(struct node_base_ctx *ctx, struct node_common *node1, struct node_common *node2)
{
}

DEFINE_STATIC_CALL_NULL(__static_manipulate_2_1, default_manipulate_2_1);

static void static_manipulate_2_1(struct node_base_ctx *ctx, struct node_common *node1, struct node_common *node2)
{
	static_call(__static_manipulate_2_1)(ctx, node1, node2);
}

// static_manipulate_2_2
static void default_manipulate_2_2(struct node_base_ctx *ctx, struct node_common *node1, struct node_common *node2)
{
}

DEFINE_STATIC_CALL_NULL(__static_manipulate_2_2, default_manipulate_2_2);

static void static_manipulate_2_2(struct node_base_ctx *ctx, struct node_common *node1, struct node_common *node2)
{
	static_call(__static_manipulate_2_2)(ctx, node1, node2);
}

// static_manipulate_2_3
static void default_manipulate_2_3(struct node_base_ctx *ctx, struct node_common *node1, struct node_common *node2)
{
}

DEFINE_STATIC_CALL_NULL(__static_manipulate_2_3, default_manipulate_2_3);

static void static_manipulate_2_3(struct node_base_ctx *ctx, struct node_common *node1, struct node_common *node2)
{
	static_call(__static_manipulate_2_3)(ctx, node1, node2);
}

// static_manipulate_2_4
static void default_manipulate_2_4(struct node_base_ctx *ctx, struct node_common *node1, struct node_common *node2)
{
}

DEFINE_STATIC_CALL_NULL(__static_manipulate_2_4, default_manipulate_2_4);

static void static_manipulate_2_4(struct node_base_ctx *ctx, struct node_common *node1, struct node_common *node2)
{
	static_call(__static_manipulate_2_4)(ctx, node1, node2);
}

// static_manipulate_3_1
static void default_manipulate_3_1(struct node_base_ctx *ctx, struct node_common *node1, struct node_common *node2, struct node_common *node3)
{
}

DEFINE_STATIC_CALL_NULL(__static_manipulate_3_1, default_manipulate_3_1);

static void static_manipulate_3_1(struct node_base_ctx *ctx, struct node_common *node1, struct node_common *node2, struct node_common *node3)
{
	static_call(__static_manipulate_3_1)(ctx, node1, node2, node3);
}

// static_manipulate_3_2
static void default_manipulate_3_2(struct node_base_ctx *ctx, struct node_common *node1, struct node_common *node2, struct node_common *node3)
{
}

DEFINE_STATIC_CALL_NULL(__static_manipulate_3_2, default_manipulate_3_2);

static void static_manipulate_3_2(struct node_base_ctx *ctx, struct node_common *node1, struct node_common *node2, struct node_common *node3)
{
	static_call(__static_manipulate_3_2)(ctx, node1, node2, node3);
}

// static_manipulate_4_1
static void default_manipulate_4_1(struct node_base_ctx *ctx, struct node_common *node1, struct node_common *node2, struct node_common *node3, struct node_common *node4)
{
}

DEFINE_STATIC_CALL_NULL(__static_manipulate_4_1, default_manipulate_4_1);

static void static_manipulate_4_1(struct node_base_ctx *ctx, struct node_common *node1, struct node_common *node2, struct node_common *node3, struct node_common *node4)
{
	static_call(__static_manipulate_4_1)(ctx, node1, node2, node3, node4);
}

static void set_default_static_funcs(void) 
{
	static_call_update(__static_user_configure, default_user_configure);
	static_call_update(__static_init_meta, default_init_meta);
	static_call_update(__static_lookup, default_lookup);
	static_call_update(__static_update, default_update);
	static_call_update(__static_delete, default_delete);
	static_call_update(__static_manipulate, default_manipulate);
	static_call_update(__static_manipulate_2, default_manipulate_2);
	static_call_update(__static_manipulate_3, default_manipulate_3);
	static_call_update(__static_manipulate_4, default_manipulate_4);
}

int reg_node_base_ext_ops(struct node_base_ext_ops *new_ext_ops) 
{
	int res = 0;
	spin_lock(&static_ops_lock);
	if (bpf_ops != NULL) {
		res = -EEXIST;
		goto error;
	}
	if (!bpf_try_module_get(new_ext_ops, new_ext_ops->owner)) {
		pr_err("failed to get bpf module");
		goto error;
	}
	bpf_ops = new_ext_ops;
	/* we have get bpf module now*/
	if (new_ext_ops->lookup != NULL) {
		static_call_update(__static_lookup, new_ext_ops->lookup);
		pr_debug("node_base update lookup");
	} 
	if (new_ext_ops->update != NULL) {
		static_call_update(__static_update, new_ext_ops->update);
		pr_debug("mod_struct_ops_demo update update");
	} 
	if (new_ext_ops->user_configure != NULL) {
		static_call_update(__static_user_configure, new_ext_ops->user_configure);
		pr_debug("mod_struct_ops_demo update user_configure");
	} 
	if (new_ext_ops->init_meta != NULL) {
		static_call_update(__static_init_meta, new_ext_ops->init_meta);
		pr_debug("mod_struct_ops_demo update init_meta");
	} 
	if (new_ext_ops->delete != NULL) {
		static_call_update(__static_delete, new_ext_ops->delete);
		pr_debug("mod_struct_ops_demo update delete");
	} 
	if (new_ext_ops->manipulate != NULL) {
		static_call_update(__static_manipulate, new_ext_ops->manipulate);
		pr_debug("mod_struct_ops_demo update manipulate");
	} 

	spin_unlock(&static_ops_lock);
	return 0;
error:
	spin_unlock(&static_ops_lock);
	return res; 
}
EXPORT_SYMBOL(reg_node_base_ext_ops);

void unreg_node_base_ext_ops(struct node_base_ext_ops *ops)
{
	spin_lock(&static_ops_lock);
	if (bpf_ops != NULL) {
		bpf_module_put(bpf_ops, bpf_ops->owner);
		bpf_ops = NULL;
		set_default_static_funcs();
	}
	spin_unlock(&static_ops_lock);
}
EXPORT_SYMBOL(unreg_node_base_ext_ops);

static void __always_inline add_to_freelist(struct node_base_ctx *ctx, struct node_common *node)
{
	struct node_common *tmp; 
	tmp = ctx->free_list;
	node->next_to_free = tmp; 
	ctx->free_list = node;
}

//common pattern for single list add entry: assume, node2->child[0] == NULL
//tmp = node1->child[0]; node1->child[0] = node2, node2->child[0] = tmp; 
static int __always_inline  ____node_list_add_entry(struct node_base_ctx *ctx, u32 child_idx, struct node_common *node1, struct node_common *node2) 
{
	if (likely(node2->childs[child_idx] == NULL)) {
		struct node_common *tmp = node1->childs[child_idx];
		node1->childs[child_idx] = node2;
		node2->childs[child_idx] = tmp;
		node2->ref_cnt += 1;
		return 0;
	}
	return -1;
}

//common pattern for single list del entry: assume, node1->next = node2
//node1->next = node2->next , node2->next = NULL, try to add node2 to freelist 
static int __always_inline ____node_list_del_entry(struct node_base_ctx *ctx, u32 child_idx, struct node_common *node1, struct node_common *node2)
{
	if (likely(node1->childs[child_idx] == node2)) {
		node1->childs[child_idx] = node2->childs[child_idx];
		node2->childs[child_idx] = NULL;
		if (--node2->ref_cnt == 0) 
			add_to_freelist(ctx, node2);
		return 0;
	}
	return -1;
}

// static int __always_inline ____node_list_add_head(struct node_base_ctx *ctx, u32 child_idx, struct node_common *node)
// {
// 	if (likely(node->childs[child_idx] == NULL)) {
// 		struct node_common *old = *(ctx->pproot);
// 		node->childs[child_idx] = old;
// 		*(ctx->pproot) = node;
// 		node->ref_cnt += 1;
// 		return 0;
// 	}
// 	return -1;
// }

// static void __always_inline ____node_list_del_head(struct node_base_ctx *ctx, u32 child_idx)
// {
// 	struct node_common *old = *(ctx->pproot);
// 	if (old == NULL) {
// 		return;
// 	}
// 	*(ctx->pproot) = old->childs[child_idx];
// 	if (--old->ref_cnt == 0) {
// 		add_to_freelist(ctx, old);
// 	}
// }

static void __always_inline ____node_del_child(struct node_base_ctx *ctx, u32 child_idx, struct node_common *node)
{
	struct node_common *pchild = node->childs[child_idx];
	if (pchild != NULL) {
		if (--pchild->ref_cnt == 0) {
			add_to_freelist(ctx, pchild);
		}
		node->childs[child_idx] = NULL;   
	}
}

//common pattern for single list add entry: assume, node2->child[0] == NULL
//tmp = node1->child[0]; node1->child[0] = node2; node2->child[0] = tmp
//node2->
static int __always_inline  ____node_list_add_double_entry(struct node_base_ctx *ctx, u32 child_next, u32 child_prev, struct node_common *node1, struct node_common *node2) 
{
	struct node_common *node3 = node1->childs[child_next];
	if (unlikely(!(node2->childs[child_next] == NULL && node2->childs[child_prev] == NULL) || node3 == NULL))
		return -1;
	if (node3 == node1 && node1->childs[child_prev] == node1) {
		//we only have node1 
		node1->childs[child_next] = node2;
		node1->childs[child_prev] = node2;
		node2->childs[child_next] = node1;
		node2->childs[child_prev] = node1;
		node2->ref_cnt += 2;
		return 0;
	} else if (node3->childs[child_prev] == node1 && node1->childs[child_next] == node3) {
		//node3 and node1 are connected
		node1->childs[child_next] = node2;
		node2->childs[child_next] = node3;
		node3->childs[child_prev] = node2;
		node2->childs[child_prev] = node1;
		node2->ref_cnt += 2;
		return 0;
	} else {
		return -1;
	}
}

//return 1 if list is empty
static int __always_inline  ____node_list_del_double_entry(struct node_base_ctx *ctx, u32 child_next, u32 child_prev, struct node_common *node) 
{
	struct node_common *pre_node = node->childs[child_prev];
	struct node_common *next_node = node->childs[child_next];
	if (unlikely(pre_node == NULL || next_node == NULL))
		return -1; 
	if (pre_node == next_node) {
		if (pre_node == node) {
			//only have one node 
			return 1;
		} else if (pre_node->childs[child_prev] == pre_node->childs[child_next] && pre_node->childs[child_prev] == node) {
			//have two node, pre_node and next node is the same 
			node->childs[child_next] = NULL;
			node->childs[child_prev] = NULL;
			pre_node->childs[child_prev] = pre_node;
			pre_node->childs[child_next] = pre_node;
			node->ref_cnt-=2;
			if (node->ref_cnt == 0)
				add_to_freelist(ctx, node);
			return 0;
		} else {
			return -1;
		}
	} else if (pre_node->childs[child_next] == node && next_node->childs[child_prev] == node) {
		//we have three node 
		pre_node->childs[child_next] = next_node;
		next_node->childs[child_prev] = pre_node;
		node->childs[child_next] = NULL;
		node->childs[child_prev] = NULL;
		node->ref_cnt-=2;
		if (node->ref_cnt == 0)
			add_to_freelist(ctx, node);
		return 0;
	} else {
		return -1;
	}
}

// 0 not empty
static int __always_inline  ____node_list_double_isempty(struct node_base_ctx *ctx, u32 child_next, u32 child_prev, struct node_common *head) 
{
	return head->childs[child_next] == head->childs[child_prev] && head->childs[child_next] == head;
}

static int __always_inline  ____node_destory_empty_list(struct node_base_ctx *ctx, u32 child_next, u32 child_prev, struct node_common *head) 
{
	if (____node_list_double_isempty(ctx, child_next, child_prev, head)) {
		head->childs[child_next] = NULL;
		head->childs[child_prev] = NULL;
		head->ref_cnt -= 2;
		if (head->ref_cnt == 0) 
			add_to_freelist(ctx, head);
		return 0;
	}
	return -1;
}

static int __always_inline  ____node_init_double_list(struct node_base_ctx *ctx, u32 child_next, u32 child_prev, struct node_common *head) 
{
	if (unlikely (head->childs[child_next] != NULL || head->childs[child_prev]))
		return -1;
	head->childs[child_next]  = head;
	head->childs[child_prev]  = head;
	head->ref_cnt += 2;
	return 0;
}

//1: last: 0: not last  
static int __always_inline  ____node_is_last(struct node_base_ctx *ctx, u32 child_next, u32 child_prev, struct node_common *head, struct node_common *node) 
{
	return head->childs[child_prev] == node && node->childs[child_next] == head;
}	

//1: first: 0: not first  
static int __always_inline  ____node_is_first(struct node_base_ctx *ctx, u32 child_next, u32 child_prev, struct node_common *head, struct node_common *node) 
{
	return head->childs[child_next] == node && node->childs[child_prev] == head;
}	

// //common pattern for single list add entry: assume, node2->child[0] == NULL
// //tmp = node1->child[0]; node1->child[0] = node2; node2->child[0] = tmp
// //node2->
// static int __always_inline  ____node_list_add_double_entry(struct node_base_ctx *ctx, u32 child_next, u32 child_prev, struct node_common *node1, struct node_common *node2) 
// {
// 	struct node_common *node3 = node1->childs[child_next];
// 	if (unlikely(!(node2->childs[child_next] == NULL && node2->childs[child_prev] == NULL)))
// 		return -1;
// 	if (node3 == NULL) {
// 		node1->childs[child_next] = node2; 
// 		node2->childs[child_prev] = node1;
// 		node2->ref_cnt += 1;
// 		node1->ref_cnt += 1;
// 		return 0;
// 	} else {
// 		if (likely(node3->childs[child_prev] == node1)) {
// 			node1->childs[child_next] = node2;
// 			node2->childs[child_next] = node3;
// 			node3->childs[child_prev] = node2;
// 			node2->childs[child_prev] = node1;
// 			node2->ref_cnt += 2;
// 			return 0;
// 		} else {
// 			return -1;
// 		}
// 	}
// }

// static int __always_inline ____node_list_add_double_head(struct node_base_ctx *ctx, u32 child_next, u32 child_prev, struct node_common *node)
// {
// 	if (likely(node->childs[child_next] == NULL && node->childs[child_prev] == NULL))
// 	{
// 		struct node_common *node2 = *(ctx->pproot);
// 		if (node2 == NULL) {
// 			*(ctx->pproot) = node;  
// 			//node->childs[prev] is NULL alwraedy 
// 			//node->childs[next] is NULL alwraedy 
// 			node->ref_cnt++;
// 			return 0;
// 		} else if (node2->childs[child_prev] == NULL) {
// 			*(ctx->pproot) = node;
// 			//node1->childs[child_prev] is NULL now 
// 			node->childs[child_next] = node2;
// 			node2->childs[child_prev] = node;
// 			node->ref_cnt += 2;
// 			return 0;
// 		} else {
// 			//not sasify 
// 			return -1;
// 		}
// 	}
// 	return -1;
// }


// static int __always_inline ____node_list_del_double_head(struct node_base_ctx *ctx, u32 child_next, u32 child_prev)
// {
// 	struct node_common *node; 
// 	node = *(ctx->pproot);
// 	if (node == NULL)
// 		return 0; 
// 	if (likely(node->childs[child_prev] == NULL)) {
// 		struct node_common *node2 = node->childs[child_next];
// 		if (node2 == NULL) {
// 			*(ctx->pproot) = NULL;  
// 			//node->childs[prev] is NULL alwraedy 
// 			//node->childs[next] is NULL alwraedy 
// 			if (--node->ref_cnt == 0)
// 				add_to_freelist(ctx, node);
// 			return 0;
// 		} else if (node2->childs[child_prev] == node) {
// 			*(ctx->pproot) = node2;  //node2 ref+1, node1 ref -1 
// 			node2->childs[child_prev] = NULL; //node1 refcnt -1;
// 			node->childs[child_next] = NULL; //node2 ref-1
// 			//node1->childs[child_prev] is NULL now
// 			node->ref_cnt -= 2;
// 			if (node->ref_cnt == 0) 
// 				add_to_freelist(ctx, node);
// 			return 0;
// 		} else {
// 			//not sasify 
// 			return -1;
// 		}
// 	}
// 	return -1;
// }

// static int __always_inline ____node_list_del_double_entry(struct node_base_ctx *ctx,  u32 child_next, u32 child_prev, struct node_common *node2)
// {	
// 	struct node_common *node1, *node3;
// 	node1 = node2->childs[child_prev];
// 	node3 = node2->childs[child_next];
// 	if (node1 == NULL && node3 == NULL) {
// 		return 0;
// 	} else if (node1 == NULL) {
// 		//not head without root 
// 		if (*(ctx->pproot) == node2) {
// 			return ____node_list_del_double_head(ctx, child_next, child_prev);
// 		} else {
// 			//node 1 is NULL, not in root, node 2 3 is not NULL
// 			node2->childs[child_next] = NULL;
// 			node3->childs[child_prev] = NULL;
// 			if (--node2->ref_cnt == 0) 
// 				add_to_freelist(ctx, node1);
// 			if (--node3->ref_cnt == 0) 
// 				add_to_freelist(ctx, node2);
// 			return 0; 
// 		}
// 	} else if (node3 == NULL) {
// 		node1->childs[child_next] =  NULL;
// 		node2->childs[child_prev] = NULL;
// 		if (--node1->ref_cnt == 0) 
// 			add_to_freelist(ctx, node1);
// 		if (--node2->ref_cnt == 0) 
// 			add_to_freelist(ctx, node2);
// 		return 0;
// 	} else {
// 		//node1 != NULL node2 != NULL
// 		if (likely(node1->childs[child_next] == node2 && node3->childs[child_prev] == node2)) {
// 			node1->childs[child_next] = node3;
// 			node3->childs[child_prev] = node1;
// 			node2->childs[child_next] = NULL;
// 			node2->childs[child_prev] = NULL;
// 			node2->ref_cnt -= 2;
// 			if (node2->ref_cnt == 0) 
// 				add_to_freelist(ctx, node2);
// 			return 0;
// 		} else {
// 			return -1;
// 		}
// 	}
// }

//< 0 error;
//> 0 not NULL
//= 0 NULL
static int __always_inline ____node_check_child(struct node_common *node, u32 child_idx)
{
	return node->childs[child_idx] == NULL;
} 

/*tmp[tmp_idx] = ctx->tmps[node_idx]->childs[child_idx]*/
/*return -1 error*/
/*return 0, get a child*/
/*return 1, child is NULL*/
/*should not be called in static_manipulate_x*/
static int __always_inline ____node_getchild(struct node_base_ctx *ctx, u32 node_idx, u32 child_idx, u32 tmp_node_idx)
{ 
	//get pnode;
	struct node_common *pnode, *pchild; 
	node_idx &= (MAX_TMP_NUM - 1);
	tmp_node_idx &= (MAX_TMP_NUM - 1);
	pnode = ctx->tmps[node_idx];
	if (unlikely(pnode == NULL)) {
		pr_debug("node in tmp %d is NULL", node_idx);
		return -EINVAL;
	}
	pchild = pnode->childs[child_idx];
	if (pchild == NULL) 
		return 1;
	ctx->event = EVENT_GET_CHILD;
	static_manipulate(ctx, pchild);
	ctx->tmps[tmp_node_idx] = pchild; 
	return 0;
}

static __always_inline struct node_common*  ____alloc_new_node(struct node_base_ctx *ctx) {
	struct node_base_map *map = ctx->map;
	struct node_base_percpu_fields *fields;
	struct node_common *pnode;
	fields = this_cpu_ptr(map->percpu_fields);
	if (fields->node_num >= map->map.max_entries) {
		//最大数量
		return ERR_PTR(-ENOMEM);
	}
	pnode = bpf_mem_cache_alloc(&(fields->node_ma));
	if (pnode == NULL) {
		return pnode;
	}
	list_add(&pnode->list_node, &fields->node_list);
	add_to_freelist(ctx, pnode);
	fields->node_num++;     //释放的时候 减少节点数
	return pnode;
}

/*implementations for primitives*/
static int  __always_inline __alloc_new_node(struct node_base_ctx *ctx, int node_idx)
{
	struct node_common *pnode; 
	pnode =  ____alloc_new_node(ctx);
	if (IS_ERR_OR_NULL(pnode)) {
		return PTR_ERR(pnode);
	}
	ctx->tmps[node_idx & (MAX_TMP_NUM - 1)] = pnode; 		//directly override, we need to ensure all tmps are valid or NULL
	ctx->event = EVENT_ALLOC;
	static_manipulate(ctx, pnode);
	return 0;
}

static int __always_inline __update_to_hash(struct node_base_ctx *ctx, int node_idx, struct node_base_key_type *key)
{
	struct node_common *pnode, *element;
	struct node_base_map *map; 
	struct node_base_percpu_fields *fields;
	u32 hash;
	map = ctx->map;
	fields = this_cpu_ptr(map->percpu_fields);
	node_idx &= (MAX_TMP_NUM - 1);
	map = ctx->map;
	
	pnode = ctx->tmps[node_idx];
	if (unlikely(pnode == NULL)) {
		pr_debug("node in tmp %d is NULL", node_idx);
		return -EINVAL;
	}
	hash = xxh32(key, map->map.key_size,0);
	
	hash_for_each_possible(fields->hash_elements, element, hnode ,hash) {
		if (memcmp((void*)(element) + map->key_off, key, map->map.key_size) == 0) {
			break;
		}
	}
	if (element != NULL) 
		return -EEXIST;
	//udpate to hash
	hash_add(fields->hash_elements, &pnode->hnode, hash);
	return 0;
}

//-1 not found
static int __always_inline __get_node_by_hash(struct node_base_ctx *ctx, int node_idx)
{
	struct node_common *element;
	struct node_base_map *map; 
	struct node_base_percpu_fields *fields;
	u32 hash;
	map = ctx->map;
	fields = this_cpu_ptr(map->percpu_fields);
	node_idx &= (MAX_TMP_NUM - 1);
	map = ctx->map;
	hash = xxh32(ctx->key, map->map.key_size,0);
	hash_for_each_possible(fields->hash_elements, element, hnode ,hash) {
		if (memcmp((void*)(element) + map->key_off, ctx->key, map->map.key_size) == 0) {
			break;
		}
	}
	if (element == NULL) 
	//not fhound
		return -1;

	//directly manipulate
	ctx->event = EVENT_GET_HASH;
	static_manipulate(ctx, element);
	//write to tmps
	ctx->tmps[node_idx] = element;
	return 0;
}

//node1->childs[child_idx] = node2
static int __always_inline __node_setchild(struct node_base_ctx *ctx, struct node_common *node1, u32 child_idx, struct node_common *node2)
{
	struct node_base_map *map = ctx->map;  
	struct node_common **ppchild;
	if (unlikely(child_idx >= map->child_num)) {
		pr_debug("child_idx %d is larger than child num %d\n",child_idx, map->child_num);
		return -EINVAL;
	}
	ppchild = &(node1->childs[child_idx]);
	if (*ppchild != NULL && --(*ppchild)->ref_cnt == 0) 
		add_to_freelist(ctx, *ppchild);
	/*set child and add refcnt*/
	*ppchild = node2;
	node2->ref_cnt++; 
	return 0;
}

static int __always_inline __node_list_add_entry(struct node_base_ctx *ctx, u32 child_idx, 
						  struct node_common *node1, struct node_common *node2) 
{
	if (child_idx >= ctx->map->child_num) 
		return -1;
	return ____node_list_add_entry(ctx, child_idx, node1, node2);
}

static int __always_inline __node_list_del_entry(struct node_base_ctx *ctx, u32 child_idx, 
						  struct node_common *node1, struct node_common *node2) 
{
	if (child_idx >= ctx->map->child_num) 
		return -1;
	return ____node_list_del_entry(ctx, child_idx, node1, node2);
}

static int __always_inline __node_del_child(struct node_base_ctx *ctx, u32 child_idx, 
						  struct node_common *node) 
{
	if (child_idx >= ctx->map->child_num) 
		return -1;
	____node_del_child(ctx, child_idx, node);
	return 0;
}

static int __always_inline __manipulate_node(struct node_base_ctx *ctx, u32 node_idx)
{
	struct node_common *pnode;
	node_idx &= (MAX_TMP_NUM - 1);
	pnode = ctx->tmps[node_idx];
	if (unlikely(pnode == NULL)) {
		pr_debug("node in tmp %d is NULL", node_idx);
		return -EINVAL;
	}
	//call eBPF callback 
	static_manipulate(ctx, pnode);
	return 0;
}

//common pattern for single list add entry: assume, node2->child[0] == NULL
//tmp = node1->child[0]; node1->child[0] = node2; node2->child[0] = tmp
//node2->
static int __always_inline  __node_list_add_double_entry_fast(struct node_base_ctx *ctx, struct node_common *node1, struct node_common *node2) 
{
	return ____node_list_add_double_entry(ctx, 0, 1, node1, node2);
}

static int __always_inline  __node_list_del_double_entry_fast(struct node_base_ctx *ctx,struct node_common *node2) 
{
	return ____node_list_del_double_entry(ctx, 0, 1, node2);
}

static int __always_inline  __node_list_double_isempty_fast(struct node_base_ctx *ctx, struct node_common *head) 
{
	return ____node_list_double_isempty(ctx, 0, 1, head);
}

static int __always_inline  __node_destory_empty_list_fast(struct node_base_ctx *ctx,struct node_common *head) 
{
	return ____node_destory_empty_list(ctx, 0, 1, head);
}

static int __always_inline  __node_init_double_list_fast(struct node_base_ctx *ctx, struct node_common *head) 
{
	return ____node_init_double_list(ctx, 0, 1, head);
}

//1: last: 0: not last  
static int __always_inline  __node_list_doule_is_last_fast(struct node_base_ctx *ctx, struct node_common *head, struct node_common *node) 
{
	return ____node_is_last(ctx, 0, 1, head, node);
}	

//1: first: 0: not first  
static int __always_inline  __node_list_doule_is_first_fast(struct node_base_ctx *ctx, struct node_common *head, struct node_common *node) 
{
	return ____node_is_first(ctx, 0, 1, head, node);
}	


// __manipulate_node_1_1
static int __always_inline __manipulate_node_1_1(struct node_base_ctx *ctx, u32 node_idx)
{
	struct node_common *pnode;
	node_idx &= (MAX_TMP_NUM - 1);
	pnode = ctx->tmps[node_idx];
	if (unlikely(pnode == NULL)) {
		pr_debug("node in tmp %d is NULL", node_idx);
		return -EINVAL;
	}
	// call eBPF callback 
	static_manipulate_1_1(ctx, pnode);
	return 0;
}

// __manipulate_node_1_2
static int __always_inline __manipulate_node_1_2(struct node_base_ctx *ctx, u32 node_idx)
{
	struct node_common *pnode;
	node_idx &= (MAX_TMP_NUM - 1);
	pnode = ctx->tmps[node_idx];
	if (unlikely(pnode == NULL)) {
		pr_debug("node in tmp %d is NULL", node_idx);
		return -EINVAL;
	}
	// call eBPF callback 
	static_manipulate_1_2(ctx, pnode);
	return 0;
}

// __manipulate_node_1_3
static int __always_inline __manipulate_node_1_3(struct node_base_ctx *ctx, u32 node_idx)
{
	struct node_common *pnode;
	node_idx &= (MAX_TMP_NUM - 1);
	pnode = ctx->tmps[node_idx];
	if (unlikely(pnode == NULL)) {
		pr_debug("node in tmp %d is NULL", node_idx);
		return -EINVAL;
	}
	// call eBPF callback 
	static_manipulate_1_3(ctx, pnode);
	return 0;
}

// __manipulate_node_1_4
static int __always_inline __manipulate_node_1_4(struct node_base_ctx *ctx, u32 node_idx)
{
	struct node_common *pnode;
	node_idx &= (MAX_TMP_NUM - 1);
	pnode = ctx->tmps[node_idx];
	if (unlikely(pnode == NULL)) {
		pr_debug("node in tmp %d is NULL", node_idx);
		return -EINVAL;
	}
	// call eBPF callback 
	static_manipulate_1_4(ctx, pnode);
	return 0;
}

// __manipulate_nodes_2_1
static int __always_inline __manipulate_nodes_2_1(struct node_base_ctx *ctx, u32 node_idx1, u32 node_idx2)
{
	struct node_common *pnode1, *pnode2;
	node_idx1 &= (MAX_TMP_NUM - 1);
	node_idx2 &= (MAX_TMP_NUM - 1);
	pnode1 = ctx->tmps[node_idx1];
	pnode2 = ctx->tmps[node_idx2];

	if (unlikely(pnode1 == NULL || pnode2 == NULL)) {
		pr_debug("node in tmp %d is NULL", node_idx1);
		return -EINVAL;
	}
	// call eBPF callback 
	static_manipulate_2_1(ctx, pnode1, pnode2);
	return 0;
}

// __manipulate_nodes_2_2
static int __always_inline __manipulate_nodes_2_2(struct node_base_ctx *ctx, u32 node_idx1, u32 node_idx2)
{
	struct node_common *pnode1, *pnode2;
	node_idx1 &= (MAX_TMP_NUM - 1);
	node_idx2 &= (MAX_TMP_NUM - 1);
	pnode1 = ctx->tmps[node_idx1];
	pnode2 = ctx->tmps[node_idx2];

	if (unlikely(pnode1 == NULL || pnode2 == NULL)) {
		pr_debug("node in tmp %d is NULL", node_idx1);
		return -EINVAL;
	}
	// call eBPF callback 
	static_manipulate_2_2(ctx, pnode1, pnode2);
	return 0;
}

// __manipulate_nodes_2_3
static int __always_inline __manipulate_nodes_2_3(struct node_base_ctx *ctx, u32 node_idx1, u32 node_idx2)
{
	struct node_common *pnode1, *pnode2;
	node_idx1 &= (MAX_TMP_NUM - 1);
	node_idx2 &= (MAX_TMP_NUM - 1);
	pnode1 = ctx->tmps[node_idx1];
	pnode2 = ctx->tmps[node_idx2];

	if (unlikely(pnode1 == NULL || pnode2 == NULL)) {
		pr_debug("node in tmp %d is NULL", node_idx1);
		return -EINVAL;
	}
	// call eBPF callback 
	static_manipulate_2_3(ctx, pnode1, pnode2);
	return 0;
}

// __manipulate_nodes_2_4
static int __always_inline __manipulate_nodes_2_4(struct node_base_ctx *ctx, u32 node_idx1, u32 node_idx2)
{
	struct node_common *pnode1, *pnode2;
	node_idx1 &= (MAX_TMP_NUM - 1);
	node_idx2 &= (MAX_TMP_NUM - 1);
	pnode1 = ctx->tmps[node_idx1];
	pnode2 = ctx->tmps[node_idx2];

	if (unlikely(pnode1 == NULL || pnode2 == NULL)) {
		pr_debug("node in tmp %d is NULL", node_idx1);
		return -EINVAL;
	}
	// call eBPF callback 
	static_manipulate_2_4(ctx, pnode1, pnode2);
	return 0;
}

// __manipulate_nodes_3_1
static int __always_inline __manipulate_nodes_3_1(struct node_base_ctx *ctx, u32 node_idx1, u32 node_idx2, u32 node_idx3)
{
	struct node_common *pnode1, *pnode2, *pnode3;
	node_idx1 &= (MAX_TMP_NUM - 1);
	node_idx2 &= (MAX_TMP_NUM - 1);
	node_idx3 &= (MAX_TMP_NUM - 1);
	pnode1 = ctx->tmps[node_idx1];
	pnode2 = ctx->tmps[node_idx2];
	pnode3 = ctx->tmps[node_idx3];

	if (unlikely(pnode1 == NULL || pnode2 == NULL || pnode3 == NULL)) {
		pr_debug("node in tmp %d is NULL", node_idx1);
		return -EINVAL;
	}
	// call eBPF callback 
	static_manipulate_3_1(ctx, pnode1, pnode2, pnode3);
	return 0;
}

// __manipulate_nodes_3_2
static int __always_inline __manipulate_nodes_3_2(struct node_base_ctx *ctx, u32 node_idx1, u32 node_idx2, u32 node_idx3)
{
	struct node_common *pnode1, *pnode2, *pnode3;
	node_idx1 &= (MAX_TMP_NUM - 1);
	node_idx2 &= (MAX_TMP_NUM - 1);
	node_idx3 &= (MAX_TMP_NUM - 1);
	pnode1 = ctx->tmps[node_idx1];
	pnode2 = ctx->tmps[node_idx2];
	pnode3 = ctx->tmps[node_idx3];

	if (unlikely(pnode1 == NULL || pnode2 == NULL || pnode3 == NULL)) {
		pr_debug("node in tmp %d is NULL", node_idx1);
		return -EINVAL;
	}
	// call eBPF callback 
	static_manipulate_3_2(ctx, pnode1, pnode2, pnode3);
	return 0;
}

// __manipulate_nodes_4_1
static int __always_inline __manipulate_nodes_4_1(struct node_base_ctx *ctx, u32 node_idx1, u32 node_idx2, u32 node_idx3, u32 node_idx4)
{
	struct node_common *pnode1, *pnode2, *pnode3, *pnode4;
	node_idx1 &= (MAX_TMP_NUM - 1);
	node_idx2 &= (MAX_TMP_NUM - 1);
	node_idx3 &= (MAX_TMP_NUM - 1);
	node_idx4 &= (MAX_TMP_NUM - 1);
	pnode1 = ctx->tmps[node_idx1];
	pnode2 = ctx->tmps[node_idx2];
	pnode3 = ctx->tmps[node_idx3];
	pnode4 = ctx->tmps[node_idx4];

	if (unlikely(pnode1 == NULL || pnode2 == NULL || pnode3 == NULL || pnode4 == NULL)) {
		pr_debug("node in tmp %d is NULL", node_idx1);
		return -EINVAL;
	}
	// call eBPF callback 
	static_manipulate_4_1(ctx, pnode1, pnode2, pnode3, pnode4);
	return 0;
}

/*tmp[tmp_idx] = ctx->tmps[node_idx]->childs[child_idx]*/
/*return -1 error*/
/*return 0, get a child*/
/*return 1, child is NULL*/
/*should not be called in static_manipulate_x*/
static int __always_inline __node_getchild(struct node_base_ctx *ctx, u32 node_idx, u32 child_idx, u32 tmp_node_idx)
{ 
	struct node_base_map *map = ctx->map;
	if (unlikely(child_idx >= map->child_num)) {
		pr_debug("child_idx %d is larger than child num %d\n",child_idx, map->child_num);
		return -EINVAL;
	}
	return ____node_getchild(ctx, node_idx, child_idx, tmp_node_idx);
}

static int __always_inline __node_getchild_fast(struct node_base_ctx *ctx, u32 node_idx,  u32 tmp_node_idx)
{ 
	return ____node_getchild(ctx, node_idx, 0, tmp_node_idx);
}

/*tmp[tmp_idx] = ctx->tmps[node_idx]->childs[child_idx]*/
static int __always_inline __node_base_set_root(struct node_base_ctx *ctx, struct node_common *node)
{ 
	
	struct node_common *old = *(ctx->pproot);
	if (old != NULL && --old->ref_cnt == 0)
		add_to_freelist(ctx, old);
	*(ctx->pproot) = node; 
	node->ref_cnt++;
	return 0;
}

/*tmp[tmp_idx] = ctx->tmps[node_idx]->childs[child_idx]*/
/* <0 error, 0 success , 1 root is NULL, if root is NULL init one root*/
static int __always_inline __node_base_get_root(struct node_base_ctx *ctx, u32 node_idx)
{ 
	struct node_common *pnode;
	node_idx &= (MAX_TMP_NUM - 1);
	if (*(ctx->pproot) == NULL) {
		// try to alloc a new node 
		pnode = ____alloc_new_node(ctx); //manipuate here
		if (IS_ERR_OR_NULL(pnode)) {
			return PTR_ERR(pnode);
		}
		*(ctx->pproot) = pnode;
		ctx->event = EVENT_GET_ROOT_ALLOC;
		static_manipulate(ctx, *(ctx->pproot));
	} else {
		ctx->event = EVENT_GET_ROOT;
		static_manipulate(ctx, *(ctx->pproot));
	}
	ctx->tmps[node_idx] = *(ctx->pproot);
	return 0;
}

//key is always valid
static void __always_inline __node_write_key(struct node_base_ctx *ctx, struct node_common *node)
{
	u32 key_size = ctx->map->map.key_size;
	u32 key_off = ctx->map->key_off;
	memcpy((void*)node + key_off, (void*)ctx->key, key_size);
}

static void __always_inline __node_write_value(struct node_base_ctx *ctx, struct node_common *node)
{
	if (ctx->value == NULL)
		return;
	u32 val_size = ctx->map->map.value_size;
	u32 val_off = ctx->map->value_off;
	memcpy((void*)node + val_off, (void*)ctx->value, val_size);
}

//return cmp(node->key, ctx->key)
static int __always_inline __node_compare_key(struct node_base_ctx *ctx, struct node_common *node)
{
	u32 key_size = ctx->map->map.key_size;
	u32 key_off =  ctx->map->key_off;
	return memcmp((void*)node + key_off, ctx->key, key_size);
}

static void __always_inline __node_get_val_u64(struct node_base_ctx *ctx, struct node_common *node, u64* res)
{
	if (ctx->map->map.value_size != sizeof(u64)) 
		return;
	*res =  *(u64*)((void*)node + ctx->map->value_off);
	return;
} 

static void __always_inline __node_set_val_u64(struct node_base_ctx *ctx, struct node_common *node, u64 val)
{
	if (ctx->map->map.value_size != sizeof(u64)) 
		return;
	*(u64*)((void*)node + ctx->map->value_off) = val;
	return;
} 


static int __always_inline __node_check_child(struct node_base_ctx *ctx, struct node_common *node, u32 child_idx)
{
	if (child_idx >= ctx->map->child_num)
		return -1;
	return ____node_check_child(node, child_idx);
} 

static int __always_inline __node_check_child_fast(struct node_common *node)
{
	return ____node_check_child(node, 0);
} 

__bpf_kfunc int alloc_new_node(struct node_base_ctx *ctx, int node_idx)
{
    return __alloc_new_node(ctx, node_idx);
}
EXPORT_SYMBOL_GPL(alloc_new_node);

__bpf_kfunc int update_to_hash(struct node_base_ctx *ctx, int node_idx, struct node_base_key_type *key)
{
    return __update_to_hash(ctx, node_idx, key);
}
EXPORT_SYMBOL_GPL(update_to_hash);

__bpf_kfunc int get_node_by_hash(struct node_base_ctx *ctx, int node_idx)
{
    return __get_node_by_hash(ctx, node_idx);
}
EXPORT_SYMBOL_GPL(get_node_by_hash);

__bpf_kfunc int node_setchild(struct node_base_ctx *ctx, struct node_common *node1, u32 child_idx, struct node_common *node2)
{
    return __node_setchild(ctx, node1, child_idx, node2);
}
EXPORT_SYMBOL_GPL(node_setchild);

__bpf_kfunc int node_list_add_entry(struct node_base_ctx *ctx, u32 child_idx, struct node_common *node1, struct node_common *node2)
{
    return __node_list_add_entry(ctx, child_idx, node1, node2);
}
EXPORT_SYMBOL_GPL(node_list_add_entry);

__bpf_kfunc int node_list_del_entry(struct node_base_ctx *ctx, u32 child_idx, struct node_common *node1, struct node_common *node2)
{
    return __node_list_del_entry(ctx, child_idx, node1, node2);
}
EXPORT_SYMBOL_GPL(node_list_del_entry);

__bpf_kfunc int node_del_child(struct node_base_ctx *ctx, u32 child_idx, struct node_common *node)
{
    return __node_del_child(ctx, child_idx, node);
}
EXPORT_SYMBOL_GPL(node_del_child);

__bpf_kfunc int manipulate_node(struct node_base_ctx *ctx, u32 node_idx)
{
    return __manipulate_node(ctx, node_idx);
}
EXPORT_SYMBOL_GPL(manipulate_node);

__bpf_kfunc int node_list_add_double_entry_fast(struct node_base_ctx *ctx, struct node_common *node1, struct node_common *node2)
{
    return __node_list_add_double_entry_fast(ctx, node1, node2);
}
EXPORT_SYMBOL_GPL(node_list_add_double_entry_fast);

__bpf_kfunc int node_list_del_double_entry_fast(struct node_base_ctx *ctx, struct node_common *node2)
{
    return __node_list_del_double_entry_fast(ctx, node2);
}
EXPORT_SYMBOL_GPL(node_list_del_double_entry_fast);

__bpf_kfunc int node_list_double_isempty_fast(struct node_base_ctx *ctx, struct node_common *head)
{
    return __node_list_double_isempty_fast(ctx, head);
}
EXPORT_SYMBOL_GPL(node_list_double_isempty_fast);

__bpf_kfunc int node_destory_empty_list_fast(struct node_base_ctx *ctx, struct node_common *head)
{
    return __node_destory_empty_list_fast(ctx, head);
}
EXPORT_SYMBOL_GPL(node_destory_empty_list_fast);

__bpf_kfunc int node_init_double_list_fast(struct node_base_ctx *ctx, struct node_common *head)
{
    return __node_init_double_list_fast(ctx, head);
}
EXPORT_SYMBOL_GPL(node_init_double_list_fast);

__bpf_kfunc int node_list_doule_is_last_fast(struct node_base_ctx *ctx, struct node_common *head, struct node_common *node)
{
    return __node_list_doule_is_last_fast(ctx, head, node);
}
EXPORT_SYMBOL_GPL(node_list_doule_is_last_fast);

__bpf_kfunc int node_list_doule_is_first_fast(struct node_base_ctx *ctx, struct node_common *head, struct node_common *node)
{
    return __node_list_doule_is_first_fast(ctx, head, node);
}
EXPORT_SYMBOL_GPL(node_list_doule_is_first_fast);

__bpf_kfunc int manipulate_node_1_1(struct node_base_ctx *ctx, u32 node_idx)
{
    return __manipulate_node_1_1(ctx, node_idx);
}
EXPORT_SYMBOL_GPL(manipulate_node_1_1);

__bpf_kfunc int manipulate_node_1_2(struct node_base_ctx *ctx, u32 node_idx)
{
    return __manipulate_node_1_2(ctx, node_idx);
}
EXPORT_SYMBOL_GPL(manipulate_node_1_2);

__bpf_kfunc int manipulate_node_1_3(struct node_base_ctx *ctx, u32 node_idx)
{
    return __manipulate_node_1_3(ctx, node_idx);
}
EXPORT_SYMBOL_GPL(manipulate_node_1_3);

__bpf_kfunc int manipulate_node_1_4(struct node_base_ctx *ctx, u32 node_idx)
{
    return __manipulate_node_1_4(ctx, node_idx);
}
EXPORT_SYMBOL_GPL(manipulate_node_1_4);

__bpf_kfunc int manipulate_nodes_2_1(struct node_base_ctx *ctx, u32 node_idx1, u32 node_idx2)
{
    return __manipulate_nodes_2_1(ctx, node_idx1, node_idx2);
}
EXPORT_SYMBOL_GPL(manipulate_nodes_2_1);

__bpf_kfunc int manipulate_nodes_2_2(struct node_base_ctx *ctx, u32 node_idx1, u32 node_idx2)
{
    return __manipulate_nodes_2_2(ctx, node_idx1, node_idx2);
}
EXPORT_SYMBOL_GPL(manipulate_nodes_2_2);

__bpf_kfunc int manipulate_nodes_2_3(struct node_base_ctx *ctx, u32 node_idx1, u32 node_idx2)
{
    return __manipulate_nodes_2_3(ctx, node_idx1, node_idx2);
}
EXPORT_SYMBOL_GPL(manipulate_nodes_2_3);

__bpf_kfunc int manipulate_nodes_2_4(struct node_base_ctx *ctx, u32 node_idx1, u32 node_idx2)
{
    return __manipulate_nodes_2_4(ctx, node_idx1, node_idx2);
}
EXPORT_SYMBOL_GPL(manipulate_nodes_2_4);

__bpf_kfunc int manipulate_nodes_3_1(struct node_base_ctx *ctx, u32 node_idx1, u32 node_idx2, u32 node_idx3)
{
    return __manipulate_nodes_3_1(ctx, node_idx1, node_idx2, node_idx3);
}
EXPORT_SYMBOL_GPL(manipulate_nodes_3_1);

__bpf_kfunc int manipulate_nodes_3_2(struct node_base_ctx *ctx, u32 node_idx1, u32 node_idx2, u32 node_idx3)
{
    return __manipulate_nodes_3_2(ctx, node_idx1, node_idx2, node_idx3);
}
EXPORT_SYMBOL_GPL(manipulate_nodes_3_2);

__bpf_kfunc int manipulate_nodes_4_1(struct node_base_ctx *ctx, u32 node_idx1, u32 node_idx2, u32 node_idx3, u32 node_idx4)
{
    return __manipulate_nodes_4_1(ctx, node_idx1, node_idx2, node_idx3, node_idx4);
}
EXPORT_SYMBOL_GPL(manipulate_nodes_4_1);

__bpf_kfunc int node_getchild(struct node_base_ctx *ctx, u32 node_idx, u32 child_idx, u32 tmp_node_idx)
{
    return __node_getchild(ctx, node_idx, child_idx, tmp_node_idx);
}
EXPORT_SYMBOL_GPL(node_getchild);

__bpf_kfunc int node_getchild_fast(struct node_base_ctx *ctx, u32 node_idx, u32 tmp_node_idx)
{
    return __node_getchild_fast(ctx, node_idx, tmp_node_idx);
}
EXPORT_SYMBOL_GPL(node_getchild_fast);

__bpf_kfunc int node_base_set_root(struct node_base_ctx *ctx, struct node_common *node)
{
    return __node_base_set_root(ctx, node);
}
EXPORT_SYMBOL_GPL(node_base_set_root);

__bpf_kfunc int node_base_get_root(struct node_base_ctx *ctx, u32 node_idx)
{
    return __node_base_get_root(ctx, node_idx);
}
EXPORT_SYMBOL_GPL(node_base_get_root);

__bpf_kfunc void node_write_key(struct node_base_ctx *ctx, struct node_common *node)
{
    __node_write_key(ctx, node);
}
EXPORT_SYMBOL_GPL(node_write_key);

__bpf_kfunc void node_write_value(struct node_base_ctx *ctx, struct node_common *node)
{
    __node_write_value(ctx, node);
}
EXPORT_SYMBOL_GPL(node_write_value);

__bpf_kfunc int node_compare_key(struct node_base_ctx *ctx, struct node_common *node)
{
    return __node_compare_key(ctx, node);
}
EXPORT_SYMBOL_GPL(node_compare_key);

__bpf_kfunc void node_get_val_u64(struct node_base_ctx *ctx, struct node_common *node, u64* res)
{
    __node_get_val_u64(ctx, node, res);
}
EXPORT_SYMBOL_GPL(node_get_val_u64);

__bpf_kfunc void node_set_val_u64(struct node_base_ctx *ctx, struct node_common *node, u64 val)
{
    __node_set_val_u64(ctx, node, val);
}
EXPORT_SYMBOL_GPL(node_set_val_u64);

__bpf_kfunc int node_check_child(struct node_base_ctx *ctx, struct node_common *node, u32 child_idx)
{
    return __node_check_child(ctx, node, child_idx);
}
EXPORT_SYMBOL_GPL(node_check_child);

__bpf_kfunc int node_check_child_fast(struct node_common *node)
{
    return __node_check_child_fast(node);
}
EXPORT_SYMBOL_GPL(node_check_child_fast);


BTF_SET8_START(bpf_ptr_base_kfunc_ids)
BTF_ID_FLAGS(func, alloc_new_node, KF_TRUSTED_ARGS);
BTF_ID_FLAGS(func, update_to_hash, KF_TRUSTED_ARGS);
BTF_ID_FLAGS(func, get_node_by_hash, KF_TRUSTED_ARGS);
BTF_ID_FLAGS(func, node_setchild, KF_TRUSTED_ARGS);
BTF_ID_FLAGS(func, node_list_add_entry, KF_TRUSTED_ARGS);
BTF_ID_FLAGS(func, node_list_del_entry, KF_TRUSTED_ARGS);
BTF_ID_FLAGS(func, node_del_child, KF_TRUSTED_ARGS);
BTF_ID_FLAGS(func, manipulate_node, KF_TRUSTED_ARGS);
BTF_ID_FLAGS(func, node_list_add_double_entry_fast, KF_TRUSTED_ARGS);
BTF_ID_FLAGS(func, node_list_del_double_entry_fast, KF_TRUSTED_ARGS);
BTF_ID_FLAGS(func, node_list_double_isempty_fast, KF_TRUSTED_ARGS);
BTF_ID_FLAGS(func, node_init_double_list_fast, KF_TRUSTED_ARGS);
BTF_ID_FLAGS(func, node_destory_empty_list_fast, KF_TRUSTED_ARGS);
BTF_ID_FLAGS(func, node_list_doule_is_first_fast, KF_TRUSTED_ARGS);
BTF_ID_FLAGS(func, node_list_doule_is_last_fast, KF_TRUSTED_ARGS);
BTF_ID_FLAGS(func, manipulate_nodes_2, KF_TRUSTED_ARGS);
BTF_ID_FLAGS(func, manipulate_node_3, KF_TRUSTED_ARGS);
BTF_ID_FLAGS(func, manipulate_node_4, KF_TRUSTED_ARGS);
BTF_ID_FLAGS(func, node_getchild, KF_TRUSTED_ARGS);
BTF_ID_FLAGS(func, node_base_set_root, KF_TRUSTED_ARGS);
BTF_ID_FLAGS(func, node_base_get_root, KF_TRUSTED_ARGS);
BTF_ID_FLAGS(func, node_write_key, KF_TRUSTED_ARGS);
BTF_ID_FLAGS(func, node_write_value, KF_TRUSTED_ARGS);
BTF_ID_FLAGS(func, node_compare_key, KF_TRUSTED_ARGS);
BTF_ID_FLAGS(func, node_get_val_u64, KF_TRUSTED_ARGS);
BTF_ID_FLAGS(func, node_set_val_u64, KF_TRUSTED_ARGS);
BTF_ID_FLAGS(func, node_check_child, KF_TRUSTED_ARGS);
BTF_ID_FLAGS(func, node_check_child_fast, KF_TRUSTED_ARGS);
BTF_ID_FLAGS(func, node_getchild_fast, KF_TRUSTED_ARGS);
BTF_SET8_END(bpf_ptr_base_kfunc_ids)

static const struct btf_kfunc_id_set bpf_ptr_base_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &bpf_ptr_base_kfunc_ids,
};

int node_base_alloc_check(union bpf_attr *attr) 
{
	struct node_base_user_config conf; 
	memset(&conf, 0, sizeof(conf));
	static_user_configure(&conf);
	// if (conf.data_size < attr->value_size) {
	// 	pr_err("data size is less than value size");
	// 	return -EINVAL;
	// }
	if (conf.child_num == 0 || attr->max_entries == 0) {
		pr_err("child_num or max_entries is 0");
		return -EINVAL;
	}
	if (attr->key_size < 4) {
		pr_err("key_size should be at leaset 4");
		return -EINVAL;
	}
	return 0;
}

static void __free_nodes(struct node_base_percpu_fields *fields)
{
	migrate_disable();
	struct node_common *entry, *n; 
	list_for_each_entry_safe(entry, n, &fields->node_list, list_node) {
		/* node is allocated in bpf_lookup_elem(with flag set to insert), free here*/
		list_del(&entry->list_node);
		bpf_mem_cache_free(&fields->node_ma, entry);
	}
	migrate_enable();
}

static __always_inline void __free_percpu_fields(struct node_base_map* node_map)
{
	int cpu;
	for_each_possible_cpu(cpu) {
		struct node_base_percpu_fields * fields = per_cpu_ptr(node_map->percpu_fields, cpu);
		__free_nodes(fields);
	}
	for_each_possible_cpu(cpu) {
		struct node_base_percpu_fields * fields = per_cpu_ptr(node_map->percpu_fields, cpu);
		bpf_mem_alloc_destroy(&fields->node_ma);
	}
}

static __always_inline int __init_percpu_fields(struct node_base_map* node_map)
{
	int cpu;
	for_each_possible_cpu(cpu) {
		struct node_base_percpu_fields * fields = per_cpu_ptr(node_map->percpu_fields, cpu);
		fields->proot = NULL;
		INIT_LIST_HEAD(&fields->node_list);
	}

	for_each_possible_cpu(cpu) {
		struct node_base_percpu_fields * fields = per_cpu_ptr(node_map->percpu_fields, cpu);
		if (bpf_mem_alloc_init(&fields->node_ma, node_map->total_size, false)) {
			/* alloc mem_alloc_cache*/
			goto error;
		}
	}

	for_each_possible_cpu(cpu) {
		struct node_base_percpu_fields * fields = per_cpu_ptr(node_map->percpu_fields, cpu);
		hash_init(fields->hash_elements);
	}


	for_each_possible_cpu(cpu) {
		struct node_base_percpu_fields * fields = per_cpu_ptr(node_map->percpu_fields, cpu);
		static_init_meta(&fields->meta);
	}

	return 0;

error:;
	__free_percpu_fields(node_map);
	return -ENOMEM;
}

static struct bpf_map *node_base_alloc(union bpf_attr *attr)
{
	struct node_base_map *node_map;
	u32 total_size, key_off, value_off, child_size;
	void *err_ptr = NULL;
	int err;
	struct node_base_user_config conf; 
	memset(&conf, 0, sizeof(conf));
	static_user_configure(&conf);
	if (conf.child_num == 0) {
		pr_err("data size is less than value size");
		return ERR_PTR(-EINVAL);
	}
	/*init main memory*/
	node_map = bpf_map_area_alloc(sizeof(*node_map), -1);
	if (node_map == NULL) {
		return ERR_PTR(-ENOMEM);
	}
	
	/*comute node size */
	child_size = conf.child_num * sizeof(void*);
	key_off = sizeof(struct node_common) + child_size;
	value_off = round_up(key_off + attr->key_size, 8);
	total_size = round_up(value_off + attr->value_size, 8);   //elem size
	
	node_map->child_num = conf.child_num;
	node_map->key_off = key_off;
	node_map->value_off = value_off;
	node_map->total_size = total_size;

	/*init percpu fields*/
	node_map->percpu_fields = __alloc_percpu_gfp(sizeof(struct node_base_percpu_fields), __alignof__(u64), GFP_USER | __GFP_NOWARN);
	if (node_map->percpu_fields == NULL) {
		pr_debug("failed to alloc percpu fields");
		err_ptr = ERR_PTR(-ENOMEM);
		goto free_node_map;
	}

	err = __init_percpu_fields(node_map);
	if (err != 0) {
		err_ptr = ERR_PTR(err);
		goto free_percpu_tag;
	}

	/*init fields*/
	return (struct bpf_map*)node_map;
	
free_percpu_tag:;
	__free_percpu_fields(node_map);
	free_percpu(node_map->percpu_fields);

free_node_map:;
	bpf_map_area_free(node_map);
	return err_ptr;
}

static void node_base_free(struct bpf_map *map) {
	struct node_base_map *node_map = (struct node_base_map*)map;
	__free_percpu_fields(node_map);
	free_percpu(node_map->percpu_fields);
	bpf_map_area_free(bmap);
}

//key is always valid 
//val depends
static void* node_base_lookup_elem(struct bpf_map *map, void *key) 
{
	struct node_base_map *node_map = (struct node_base_map*)map;
	struct node_base_ctx ctx; 
	struct node_base_percpu_fields *fields; 
	struct node_common *pnode, *current_free, *free_tmp; 
	int err; 
	bool is_same = false;
	__builtin_memset(&ctx, 0, sizeof(ctx));
	fields = this_cpu_ptr(node_map->percpu_fields);
	ctx.map = node_map;
	ctx.key = key;
	ctx.pproot = &fields->proot;
	struct node_lookup_res res;
	err = static_lookup(&ctx, &fields->meta, &res);
	res.node_idx &= (MAX_TMP_NUM - 1);
	pnode = ctx.tmps[res.node_idx];

	/*free nodes*/
	current_free = ctx.free_list;
	while (current_free != NULL) {
		if (current_free->ref_cnt > 0) {
			current_free = current_free->next_to_free;
			continue;
		}
		if (current_free == pnode)   //something wrong 
			is_same = true; 
		free_tmp = current_free->next_to_free;
		list_del(&current_free->list_node);
		if (current_free->in_hash) 
			hlist_del(&current_free->hnode);
		bpf_mem_cache_free(&fields->node_ma, current_free);
		fields->node_num--;
		current_free = free_tmp;
	}
	if (is_same) {
		pr_err("return the node which should be freed\n");
		return NULL;
	} else {	
		return (void*)pnode + node_map->value_off;
	}
}

static long node_base_update_elem(struct bpf_map *map, void *key, void *value, u64 flags) 
{
	struct node_base_map *node_map = (struct node_base_map*)map;
	struct node_base_ctx ctx; 
	struct node_base_percpu_fields *fields; 
	struct node_common *current_free, *free_tmp; 
	int err; 
	memset(&ctx, 0, sizeof(ctx));
	fields = this_cpu_ptr(node_map->percpu_fields);
	ctx.map = node_map;
	ctx.key = key;
	ctx.value = value;
	ctx.pproot = &fields->proot;
	err = static_update(&ctx, &fields->meta);
	/*free nodes*/
	current_free = ctx.free_list;
	while (current_free != NULL) {
		if (current_free->ref_cnt > 0) {
			current_free = current_free->next_to_free;
			continue;
		}
		free_tmp = current_free->next_to_free;
		list_del(&current_free->list_node);
		if (current_free->in_hash) 
			hlist_del(&current_free->hnode);
		bpf_mem_cache_free(&fields->node_ma, current_free);
		fields->node_num--;
		current_free = free_tmp;
	}
	
	return err;
}

static long node_base_delete_elem(struct bpf_map *map, void *key) {
	struct node_base_map *node_map = (struct node_base_map*)map;
	struct node_base_ctx ctx; 
	struct node_base_percpu_fields *fields; 
	struct node_common *current_free, *free_tmp; 
	int err; 
	__builtin_memset(&ctx, 0, sizeof(ctx));
	fields = this_cpu_ptr(node_map->percpu_fields);
	ctx.map = node_map;
	ctx.key = key;
	ctx.pproot = &fields->proot;
	err = static_delete(&ctx, &fields->meta);
	/*free nodes*/
	current_free = ctx.free_list;
	while (current_free != NULL) {
		if (current_free->ref_cnt > 0) {
			current_free = current_free->next_to_free;
			continue;
		}
		free_tmp = current_free->next_to_free;
		list_del(&current_free->list_node);
		if (current_free->in_hash) 
			hlist_del(&current_free->hnode);
		bpf_mem_cache_free(&fields->node_ma, current_free);
		fields->node_num--;
		current_free = free_tmp;
	}
	
	return err;
}

static u64 node_base_mem_usage(const struct bpf_map *map) 
{
	return 4;
}

static struct bpf_map_ops node_base_map_ops = {
	.map_alloc = node_base_alloc,
	.map_free = node_base_free,
	.map_lookup_elem = node_base_lookup_elem,
	.map_update_elem = node_base_update_elem,
	.map_delete_elem = node_base_delete_elem,
	.map_mem_usage = node_base_mem_usage
};

static int __init networking_pointer_base_init(void) {
	int ret = 0;
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &bpf_ptr_base_kfunc_set);
	ret = ret ?: bpf_register_static_cmap(&node_base_map_ops, THIS_MODULE);
	if (ret == 0) {
		pr_info("register networking_pointer_base");
	}
	return ret;
}

static void __exit networking_pointer_base_exit(void) {
	pr_info("unregister networking_pointer_base");
	bpf_unregister_static_cmap(THIS_MODULE);
}

/* Register module functions */
module_init(networking_pointer_base_init);
module_exit(networking_pointer_base_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chonepieceyb");
MODULE_DESCRIPTION("BPF networking datapath pointer-based data structrue sets");
MODULE_VERSION("0.01");