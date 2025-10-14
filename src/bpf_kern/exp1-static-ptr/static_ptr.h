#pragma once
#include <linux/stddef.h>

#define MAX_ENTRY 100000
#define RAND_MAX 2147483647
#define MAX_SKIPLIST_HEIGHT 16
#define MAX_SEARCH_DEPTH 65536

#define NULL_NODE_IDX (~0ULL)

#define NODE_BATCH_SIZE 128

struct pkt_5tuple_with_pad {
	__u8 pad[30];
	__u16 key;
} __attribute__((packed));

struct value_with_pad {
	__u8 pad[120];
	__u64 data;
} __attribute__((packed));

typedef struct pkt_5tuple_with_pad skip_key_type_t;
typedef struct value_with_pad skip_value_type_t;

struct sl_entry {
	skip_key_type_t key;
	skip_value_type_t value;
	//int ref_cnt;
	int height;
	__u64 next[MAX_SKIPLIST_HEIGHT];
	//int hit_cnt;
};

typedef struct sl_entry enetstl_node_type;

#define NODE_SIZE sizeof(struct sl_entry)

//HINT eNetSTL node
struct eNetSTL_node {
    union {
		/* HINT: idx to the next empty node
		*  for next_idx the low NODE_BATCH_SIZE_SHIFT bits are the index within the batch,
		*  the high bits are the index of the batch
		*/
        __u64 next_idx;  
        char data[NODE_SIZE]; //HINT: actual data storage   
    };
};

struct __node_batch {
    struct eNetSTL_node nodes[NODE_BATCH_SIZE];
};

//HINT eNetSTL node proxy 
struct eNetSTL_container {
    __u64 free_list_head;
	__u64 batches_mask; 
	__u64 capacity;
};

struct eNetSTL_proxy {
	int fd;
};

//example void ptr_release_node(ptr_node *node) __ksym;
struct eNetSTL_proxy* bpf_enetstl_create_node_proxy(void) __ksym;
struct eNetSTL_container* bpf_enetstl_get_nodes(int fd) __ksym;
void bpf_enetstl_put_nodes(struct eNetSTL_container* container) __ksym;
enetstl_node_type* bpf_enetstl_alloc_node(struct eNetSTL_container* container, u64 *idx) __ksym;
void bpf_enetstl_free_node(struct eNetSTL_container* container, u64 idx) __ksym;
int bpf_enetstl_enlarge_capacity(int fd) __ksym;
int bpf_enetstl_write_node(enetstl_node_type *node, size_t off, void *data__buf, size_t size__sz) __ksym;
void bpf_enetstl_destroy_node_proxy(struct eNetSTL_proxy* proxy) __ksym;
enetstl_node_type* bpf_enetstl_get_node(struct eNetSTL_container* container, u64 idx) __ksym;
