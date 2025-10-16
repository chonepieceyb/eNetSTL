#pragma once
#include "../vmlinux.h"
#include "../common.h"
#include <bpf/bpf_helpers.h>
#include "../bpf_experimental.h"

#define MAX_ENTRY 100000
#define RAND_MAX 2147483647
#define MAX_SKIPLIST_HEIGHT 16
#define MAX_SEARCH_DEPTH 65536

#define NULL_NODE_IDX (~0ULL)

#include "static_ptr.h"

int proxy_fd;

static __always_inline int store_proxy_into_map(struct eNetSTL_proxy *proxy) {
	int key = 0;
	struct skip_list_proxy_map_value *val = bpf_map_lookup_elem(&skiplist_map, &key);
	if (val == NULL) {
		return -1;
	}
	struct eNetSTL_proxy *old_proxy = bpf_kptr_xchg(&val->proxy, proxy);
	if (old_proxy != NULL) {
		// should not happen
		bpf_enetstl_destroy_node_proxy(old_proxy);
	}
	return 0;
}

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


static inline void connected_prev_next(enetstl_node_type *prev, int level, u64 next_node_idx) {
	size_t off = offsetof(enetstl_node_type, next) + (level & (MAX_SKIPLIST_HEIGHT - 1)) * sizeof(u64);
	bpf_enetstl_write_node(prev, off, &next_node_idx, sizeof(next_node_idx));
	// prev->next[level & (MAX_SKIPLIST_HEIGHT - 1)] = next;
}


static inline int bpf_grand()
{
	int result = 1;
	int random_num = bpf_get_prandom_u32();

	while (result < MAX_SKIPLIST_HEIGHT && (random_num > RAND_MAX / 2)) {
		++result;
		random_num = bpf_get_prandom_u32();
	}

	return result;
}

static inline void init_skiplist_head(enetstl_node_type *head)
{
	log_debug("[SKIP LIST] init_skiplist_head: initializing head");
	int height = MAX_SKIPLIST_HEIGHT;
	bpf_enetstl_write_node(head, offsetof(enetstl_node_type, height), &height, sizeof(height));
	log_debug("[SKIP LIST] init_skiplist_head: set head height to %d", head->height);
	for (int i = 0; i < MAX_SKIPLIST_HEIGHT; i++) {
		size_t off = offsetof(enetstl_node_type, next) + i * sizeof(u64);
		u64 null_idx = NULL_NODE_IDX;
		bpf_enetstl_write_node(head, off, &null_idx, sizeof(null_idx));
		// head->next[i] = NULL;
	}
	log_debug("[SKIP LIST] init_skiplist_head: head initialized with %d levels", MAX_SKIPLIST_HEIGHT);
	return;
}

// struct jump_target target = {
// 	.null_node_idx = ctx->prev_node_idx,    //prev node idx
// 	.null_off = offsetof(enetstl_node_type, next) + (ctx->level - 1) * sizeof(u64),
// 	.left_node_idx = ctx->prev_node_idx, //prev node idx
// 	.left_off = offsetof(enetstl_node_type, next) + ((ctx->level) - 1) * sizeof(u64),
// 	.right_node_idx = ctx->curr_idx,  //curr node idx
// 	.right_off = offsetof(enetstl_node_type, next) + ((ctx->level)) * sizeof(u64),
// };

struct lookup_ctx {
	struct eNetSTL_container *container;
	skip_key_type_t *target_key;
	int level;
	u32 cnt;
	u64 result_node_idx;
	struct jump_target target;
};

static long lookup_callback(__u32 index, void *data)
{
	struct lookup_ctx *ctx = (struct lookup_ctx *)data;

	if (ctx->target.null_node_idx == NULL_NODE_IDX || ctx->level < 0 || ctx->cnt >= MAX_SEARCH_DEPTH) {
		return 1; // Stop iteration
	}

	//compare target key with current node key 
	//1. left if target_key < curr key (curr key > target key), 
	//   drop down level, curr = prev->next[level - 1]
	//2. right if target_key > curr key (curr key < target key),
	//   move forward at this level, curr = curr->next[level]
	//3. if curr is NULL, this level ends, drop down level, curr = prev->next[level -1]
	u64 tmp_curr_idx = ctx->target.right_node_idx;
	ctx->cnt++;
	int cmp_res = bpf_enetstl_node_route
		(ctx->container, &ctx->target.right_node_idx,
			ctx->target_key, sizeof(skip_key_type_t), &ctx->target);
	if (cmp_res == 0) {
		//result, not modify curr idx
		log_debug("[SKIP LIST] lookup elem found key %u at level %d", ctx->target_key->key, ctx->level);
		ctx->result_node_idx = ctx->target.right_node_idx;
		return 1;
	} else if (cmp_res == 1 || cmp_res == 3) {
		//move left or null node. drop down level, (curr is updated in the func, curr = prev->next[level - 1])
		log_debug("[SKIP LIST] lookup elem move to next level, key %u, level %d", ctx->target_key->key, ctx->level - 1);
		--ctx->level;
		//update target.off
		ctx->target.null_off = offsetof(enetstl_node_type, next) + (ctx->level - 1) * sizeof(u64);  //(new level - 1)
		ctx->target.left_off = offsetof(enetstl_node_type, next) + (ctx->level - 1) * sizeof(u64);  //(new level - 1)
		ctx->target.right_off = offsetof(enetstl_node_type, next) + (ctx->level) * sizeof(u64);  //(new level)
		return 0;
	} else if (cmp_res == 2) {
		//move right, stay at this level
		log_debug("[SKIP LIST] lookup elem move forward at level %d, key %u", ctx->level, ctx->target_key->key);
		ctx->target.left_node_idx = tmp_curr_idx;
		ctx->target.null_node_idx = tmp_curr_idx;
		return 0;
	} else {
		//error
		log_error("[SKIP LIST] node route failed");
		return 1;
	}
}

static inline int init_new_entry(
	enetstl_node_type *entry, skip_key_type_t *key, skip_value_type_t *value)
{
	if (!entry || !key || !value) {
		log_debug("[SKIP LIST] init_new_entry: invalid parameters");
		return -1;
	}

	int new_height = bpf_grand();
	log_debug("[SKIP LIST] init_new_entry: new entry random height %d", new_height);
	size_t height_off = offsetof(enetstl_node_type, height);
	bpf_enetstl_write_node(entry, height_off, &new_height, sizeof(new_height));
	// entry->height = new_height;
	log_debug("[SKIP LIST] init_new_entry: allocated new entry with height %d", entry->height);

	size_t key_off = offsetof(enetstl_node_type, key);
	bpf_enetstl_write_node(entry, key_off, key, sizeof(skip_key_type_t));

	size_t value_off = offsetof(enetstl_node_type, value);
	bpf_enetstl_write_node(entry, value_off, value, sizeof(skip_value_type_t));
	log_debug("[SKIP LIST] init_new_entry: initialized new entry with key %u, value %lu", entry->key.key, entry->value.data);
	return 0;
}

static inline u64 skip_list_lookup_elem(
	struct eNetSTL_container *container,
	u64 head_idx, skip_key_type_t *key)
{
	int level = MAX_SKIPLIST_HEIGHT - 1;
	struct lookup_ctx ctx = {
		.container = container,
		.level =level,
		.cnt = 0,
		.result_node_idx = NULL_NODE_IDX,
		.target_key = key,
		.target = {
			.null_node_idx = head_idx,    //prev, prev, (level-1)
			.null_off = offsetof(enetstl_node_type, next) + (MAX_SKIPLIST_HEIGHT - 1) * sizeof(u64),
			.left_node_idx = head_idx, //prev, (level-1)
			.left_off = offsetof(enetstl_node_type, next) + (MAX_SKIPLIST_HEIGHT - 1) * sizeof(u64),
			.right_node_idx = NULL_NODE_IDX,  //curr (level), the first iter, will goto to null_node_idx and update this
			.right_off = offsetof(enetstl_node_type, next) + (MAX_SKIPLIST_HEIGHT) * sizeof(u64),
		}
	};

	log_debug("[SKIP LIST] lookup_elem: searching for key %u, start level %d", key->key, ctx.level);

	bpf_loop(MAX_SEARCH_DEPTH, lookup_callback, &ctx, 0);

	if (ctx.result_node_idx == NULL_NODE_IDX) {
		log_debug("[SKIP LIST] lookup_elem: key %u not found after %u iterations, final level %d", key->key, ctx.cnt, ctx.level);
	}

	return ctx.result_node_idx;
}

struct update_search_ctx {
	struct eNetSTL_container *container;
	u64 prev[MAX_SKIPLIST_HEIGHT];
	u64 curr_idx;
	skip_key_type_t *key;
	skip_value_type_t *value;
	int level;
	u32 cnt;
	int found;
};

static long update_search_callback(__u32 index, void *data)
{
	struct update_search_ctx *ctx = (struct update_search_ctx *)data;
	ctx->cnt++;
	log_debug("[SKIP LIST] update_elem: iter %u, level %d", ctx->cnt, ctx->level);
	if (ctx->curr_idx == NULL_NODE_IDX || ctx->level < 0 || ctx->cnt >= MAX_SEARCH_DEPTH) {
		return 1; // Stop iteration
	}
	__u32 current_level = ctx->level;
	asm_bound_check(current_level, MAX_SKIPLIST_HEIGHT);
	ctx->prev[current_level] = ctx->curr_idx;
	enetstl_node_type *curr = bpf_enetstl_get_node(ctx->container, ctx->curr_idx);
	size_t next_idx_off = offsetof(enetstl_node_type, next) + (current_level) * sizeof(u64);
	u64 next_node_idx = 0;
	bpf_enetstl_read_node(curr, next_idx_off, &next_node_idx, sizeof(next_node_idx));
	// u64 next_node_idx = curr->next[current_level];
	if (next_node_idx == NULL_NODE_IDX) {
		log_debug("[SKIP LIST] update_elem: next is NULL at level %d, dropping down", ctx->level);
		--ctx->level;
		return 0; // Continue
	}
	enetstl_node_type *next = bpf_enetstl_get_node(ctx->container, next_node_idx);
	skip_key_type_t *next_key = &next->key;
	int cmp = skip_key_cmp(next_key, ctx->key);
	if (cmp == 0) {
		log_debug("[SKIP LIST] update_elem: found existing key %u at level %d, updating value from %lu to %lu",
			  ctx->key->key, ctx->level, next->value.data, ctx->value->data);
		size_t off = offsetof(enetstl_node_type, value);
		bpf_enetstl_write_node(next, off, ctx->value, sizeof(skip_value_type_t));
		ctx->found = 1;
		return 1; // Stop iteration
	} else if (cmp > 0) {
		log_debug("[SKIP LIST] update_elem: key %u > target, dropping down from level %d", next_key->key, ctx->level);
		--ctx->level;
		return 0; // Continue
	} else {
		log_debug("[SKIP LIST] update_elem: key %u < target, moving forward at level %d", next_key->key, ctx->level);
		ctx->curr_idx = next_node_idx;
		return 0; // Continue
	}
}


static inline long skip_list_update_elem(
	struct eNetSTL_container *container,
	u64 head_idx, skip_key_type_t *key, skip_value_type_t *value)
{
	struct update_search_ctx ctx = {
		.container = container,
		.curr_idx = head_idx,
		.key = key,
		.value = value,
		.level = MAX_SKIPLIST_HEIGHT - 1,
		.cnt = 0,
		.found = 0
	};

	log_debug("[SKIP LIST] update_elem: updating key %u with value %lu", key->key, value->data);

	// Find the position where the key is expected
	bpf_loop(MAX_SEARCH_DEPTH, update_search_callback, &ctx, 0);

	if (ctx.found) {
		return 0;
	}

	log_debug("[SKIP LIST] update_elem: key %u not found after %u iterations, inserting new entry", key->key, ctx.cnt);
	// Didn't find it, we need to insert a new entry
	u64 new_entry_idx;
    enetstl_node_type *new_entry = bpf_enetstl_alloc_node(container, &new_entry_idx);
	if (new_entry == NULL) {
		return -1;
	}

	init_new_entry(new_entry, key, value);

	log_debug("[SKIP LIST] update_elem: linking new entry at all levels");
	// Link the new entry at all levels using a normal for loop
	#pragma unroll 1
	for (int i = 0; i < MAX_SKIPLIST_HEIGHT; i++) {
		if (i >= new_entry->height) {
			u64 null_idx = NULL_NODE_IDX;
			size_t off = offsetof(enetstl_node_type, next) + i * sizeof(u64);
			bpf_enetstl_write_node(new_entry, off, &null_idx, sizeof(null_idx));
			log_debug("[SKIP LIST] update_elem: level %d above height, setting next to NULL", i);
		} else {
			u64 prev_idx = ctx.prev[i];
			enetstl_node_type *prev = bpf_enetstl_get_node(container, prev_idx);
			u64 prev_next_idx = prev->next[i];
			log_debug("[SKIP LIST] update_elem: level %d linking prev idx %llu to new entry idx %llu to next idx %llu",
				  i, prev_idx, new_entry_idx, prev_next_idx);
			// Link prev to new entry
			connected_prev_next(new_entry, i, prev_next_idx);
			connected_prev_next(prev, i, new_entry_idx);
		}
	}
	return 0;
}