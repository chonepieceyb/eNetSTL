#pragma once

#include <linux/stddef.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>
#include <linux/spinlock.h>

#define MAX_SKIPLIST_HEIGHT 16

struct pkt_5tuple_with_pad {
	u8 pad[30];
	u16 key;
} __attribute__((packed));

struct value_with_pad {
	u8 pad[120];
	u64 data;
} __attribute__((packed));

typedef struct pkt_5tuple_with_pad skip_key_type_t;
typedef struct value_with_pad skip_value_type_t;

struct sl_entry {
	skip_key_type_t key;
	skip_value_type_t value;
	//int ref_cnt;
	int height;
	u64 next[MAX_SKIPLIST_HEIGHT];
	//int hit_cnt;
};

typedef struct sl_entry enetstl_node_type;

#define NODE_SIZE sizeof(struct sl_entry)

#define NODE_BATCH_SIZE_SHIFT 8
#define NODE_BATCH_SIZE (1 << NODE_BATCH_SIZE_SHIFT)
#define NODE_BATCH_MASK (NODE_BATCH_SIZE - 1)
#define DEFAULT_BATCHES_NUM 4  //HINT: default batch num when creating a new proxy, should be power of 2


//HINT eNetSTL node
struct eNetSTL_node {
    union {
		/* HINT: idx to the next empty node
		*  for next_idx the low NODE_BATCH_SIZE_SHIFT bits are the index within the batch,
		*  the high bits are the index of the batch
		*/
        u64 next_idx;  
        char data[NODE_SIZE]; //HINT: actual data storage   
    };
};

struct __node_batch {
    struct eNetSTL_node nodes[NODE_BATCH_SIZE];
};

//HINT eNetSTL node proxy 
struct eNetSTL_node_container {
    u64 free_list_head; //HINT: idx to the head of free list
	/* HINT: mask to identify valid batches, , batch_num =（batches_mask + 1）; capacity = batch_num << NODE_BATCH_SIZE_SHIFT */
	u64 batches_mask;
	u64 capacity;

	//HINT: index to the next unallocated batch, if batches_unalloc_idx == batch_num, means all batches are allocated
	u64 batches_unalloc_idx;
	int fd;  //for get proxy reserved
	struct rcu_head rcu; // For RCU callback when container is replaced
    DECLARE_FLEX_ARRAY(struct __node_batch*, batches);
};

struct eNetSTL_node_proxy {
	int fd; 
	spinlock_t lock;
	struct eNetSTL_node_container __rcu *container;
};

//wrapper for bpf kfunc
struct eNetSTL_proxy {
	int fd; 
};

//wrapper for eNetSTL_node_container
struct eNetSTL_container {
	u64 free_list_head; 
	u64 batches_mask; 
	u64 capacity;
};

static inline struct eNetSTL_node * __get_batch_idx(
	u64 idx, struct eNetSTL_node_container* container) {
	u64 batch_idx = (idx >> NODE_BATCH_SIZE_SHIFT) & container->batches_mask;
	u64 within_batch_idx = idx & NODE_BATCH_MASK;
	struct __node_batch* batch = container->batches[batch_idx];
	return &batch->nodes[within_batch_idx];
}

//note: use fd is to avoid the overhead of bpf_kptr_xchg (use spinlock), however, current appraoch lack of isolation between different users 
//the point is that it is not easy to implement a new data structure using module kfuncs (unlike bpf mpas)
struct eNetSTL_node_proxy* enetstl_create_node_proxy(void);     //HINT: create a new or get an existing node proxy structure for given fd, should be called with KF_SLEEPABLE, and put into map
struct eNetSTL_node_container* enetstl_get_nodes(int fd); 
void enetstl_put_nodes(struct eNetSTL_node_container* container);
struct eNetSTL_node* enetstl_alloc_node(struct eNetSTL_node_container* container, u64 *idx);  //HINT: alloc a new node from the node proxy, return the pointer and idx;
void enetstl_free_node(struct eNetSTL_node_container* container, u64 idx); //HINT: free the node with given idx back to the node proxy
void enetstl_enlarge_capacity(struct eNetSTL_node_container *container); //HINT: enlarge the total capacity of the proxy, this func should be called with KF_SLEEPABLE
void enetstl_destroy_node_proxy(struct eNetSTL_node_proxy* proxy);
int node_proxys_init(void);
void node_proxys_exit(void);