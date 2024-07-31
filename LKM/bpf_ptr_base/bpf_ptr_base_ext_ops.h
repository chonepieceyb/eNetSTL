#ifndef MOD_STRUCT_OPS_DEMO_H
#define MOD_STRUCT_OPS_DEMO_H

#include <linux/module.h>


#define NODE_BASE_HASH_BITS 9
#define NODE_BASE_HASH_SIZE (1 << 9)
#define META_SIZE 64
#define MAX_TMP_BITS 4
#define MAX_TMP_NUM (1 << MAX_TMP_BITS)
#define EVENT_GET_ROOT 1
#define EVENT_GET_HASH 2
#define EVENT_GET_CHILD 3
#define EVENT_ALLOC 4
#define EVENT_GET_ROOT_ALLOC 5

struct node_base_user_config {
	u32 child_num;
	//u32 data_size;
};

//64 byte user-defined ctx for manipulating node 
struct node_manipulate_ctx {
	char data[META_SIZE];
};


struct node_base_meta {
	char data[META_SIZE];
};

//64 byte common data 
struct node_user_data {
	char data[META_SIZE];
};

struct node_base_key_type {
	char data[4];
};

struct node_base_value_type {
	char data[4];
};

//lookup callback, < 0 error,  = 0 success
struct node_lookup_res {
	int node_idx; 
};

struct node_base_ctx {
	struct node_common *tmps[MAX_TMP_NUM];
	struct node_base_map *map;
	struct node_common *free_list;
	int event;
	struct node_manipulate_ctx mctx;
	struct node_common **pproot;
	void *key;   //always null
	void *value;  //could be null
};

struct node_common {
	int ref_cnt ____cacheline_aligned;
	struct list_head  list_node;   //in container 
	struct hlist_node hnode;  //hash list_node
	struct node_common *next_to_free;
	struct node_user_data user_data; 
	bool in_hash;
	DECLARE_FLEX_ARRAY(struct node_common*, childs)  ____cacheline_aligned;   //childs + key + value
};

struct node_base_ext_ops {
   	void (*user_configure)(struct node_base_user_config *config);
	void (*init_meta)(struct node_base_meta *meta);
	int (*lookup)(struct node_base_ctx *ctx, struct node_base_meta *meta, struct node_lookup_res *res);
	int (*update)(struct node_base_ctx *ctx, struct node_base_meta *meta);
	int (*delete)(struct node_base_ctx *ctx, struct node_base_meta *meta);
	void (*manipulate)(struct node_base_ctx *ctx, struct node_common *node);
	void (*manipulate_1_1)(struct node_base_ctx *ctx, struct node_common *node);
	void (*manipulate_1_2)(struct node_base_ctx *ctx, struct node_common *node);
	void (*manipulate_1_3)(struct node_base_ctx *ctx, struct node_common *node);
	void (*manipulate_1_4)(struct node_base_ctx *ctx, struct node_common *node);
	void (*manipulate_2_1)(struct node_base_ctx *ctx, struct node_common *node1, struct node_common *node2);
	void (*manipulate_2_2)(struct node_base_ctx *ctx, struct node_common *node1, struct node_common *node2);
	void (*manipulate_2_3)(struct node_base_ctx *ctx, struct node_common *node1, struct node_common *node2);
	void (*manipulate_2_4)(struct node_base_ctx *ctx, struct node_common *node1, struct node_common *node2);
	void (*manipulate_3_1)(struct node_base_ctx *ctx, struct node_common *node1, struct node_common *node2, struct node_common *node3);
	void (*manipulate_3_2)(struct node_base_ctx *ctx, struct node_common *node1, struct node_common *node2, struct node_common *node3);
	void (*manipulate_4_1)(struct node_base_ctx *ctx, struct node_common *node1, struct node_common *node2, struct node_common *node3, struct node_common *node4);
	struct module *owner;
};
#endif