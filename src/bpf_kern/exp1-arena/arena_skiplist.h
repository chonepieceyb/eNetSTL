#pragma once
#include "../vmlinux.h"
#include "../common.h"
#include "bpf_experimental.h"
#include "bpf_arena_common.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARENA);
    __uint(map_flags, BPF_F_MMAPABLE);
    __uint(max_entries, 10000); /* number of pages */
    __ulong(map_extra, 0x1ull << 44); /* start of mmap() region */
} arena SEC(".maps");

#include "bpf_arena_alloc.h"
#include "bpf_arena_list.h"

#define MAX_ENTRY 100000
#define RAND_MAX 2147483647
#define MAX_SKIPLIST_HEIGHT 16
#define MAX_SEARCH_DEPTH 65536

#define MEM_CMP_FUNC __builtin_memcmp


// Use pkt_5tuple from common.h - avoid redefinition

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
	struct sl_entry __arena *next[MAX_SKIPLIST_HEIGHT];
	//int hit_cnt;
};

typedef struct sl_entry __arena sl_entry;

static inline int skip_key_cmp(skip_key_type_t __arena *a, skip_key_type_t *b)
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
		__u16 __arena *a_ptr = (__u16 __arena *)((__u16*)a + i);
		__u16 *b_ptr = (__u16 *)((__u16*)b + i);
		cast_kern(a_ptr);
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

static inline sl_entry* ptr_get_next(sl_entry *parent, u32 idx)
{
	sl_entry **next_ptr = &parent->next[idx & (MAX_SKIPLIST_HEIGHT - 1)];
	cast_kern(next_ptr);
    sl_entry *next = *next_ptr;
	if (!next)
		return NULL;
    cast_kern(next);
    return next;
	// if (idx >= MAX_SKIPLIST_HEIGHT) {
	// 	return NULL;
	// }

	// sl_entry *next_node = parent->next[idx & (MAX_SKIPLIST_HEIGHT - 1)];
	// if (next_node == NULL)
	// 	return NULL;
	// next_node->ref_cnt++;

	// return next_node;
}

static inline void connected_prev_next(sl_entry *prev, int level, sl_entry *new_entry) {
	if (level >= MAX_SKIPLIST_HEIGHT || level < 0) {
		log_error("[SKIP LIST] connected_prev_next: level %d out of bounds", level);
		return;
	}
	if (new_entry == NULL) {
		cast_kern(prev);
		WRITE_ONCE(prev->next[level & (MAX_SKIPLIST_HEIGHT - 1)], NULL);
		return;
		// prev->next[level] = NULL;
	} else {
		//cast_user(new_entry);
		cast_kern(prev);
		sl_entry **next_ptr = &prev->next[level & (MAX_SKIPLIST_HEIGHT - 1)];
		cast_kern(next_ptr);
		cast_user(new_entry);
		//WRITE_ONCE(prev->next[level & (MAX_SKIPLIST_HEIGHT - 1)	], new_entry);
		*next_ptr = new_entry;
		return;
		// prev->next[level] = new_entry;
	}
}

static inline void ptr_release_node(sl_entry *node)
{
	// if (node == NULL) {
	// 	return;
	// }
	// if (unlikely((--node->ref_cnt) == 0)) {
	// 	node->hit_cnt ++;
	// }
    return;
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

static inline void init_skiplist_head(sl_entry *head)
{
	cast_kern(head);
	log_debug("[SKIP LIST] init_skiplist_head: initializing head");
 	head->height = MAX_SKIPLIST_HEIGHT;
	log_debug("[SKIP LIST] init_skiplist_head: set head height to %d", head->height);
	for (int i = 0; i < MAX_SKIPLIST_HEIGHT; i++) {
		head->next[i] = NULL;
	}
	log_debug("[SKIP LIST] init_skiplist_head: head initialized with %d levels", MAX_SKIPLIST_HEIGHT);
	return;
}

struct lookup_ctx {
	sl_entry *curr;
	skip_key_type_t *key;
	int level;
	u32 cnt;
	sl_entry *result;
};

static long lookup_callback(__u32 index, void *data)
{
	struct lookup_ctx *ctx = (struct lookup_ctx *)data;

	if (ctx->curr == NULL || ctx->level < 0 || ctx->cnt >= MAX_SEARCH_DEPTH) {
		return 1; // Stop iteration
	}

	cast_kern(ctx->curr);
	ctx->cnt++;
	log_debug("[SKIP LIST] lookup_elem: iter %u, level %d", ctx->cnt, ctx->level);
	sl_entry *next = ptr_get_next(ctx->curr, ctx->level);
	if (next == NULL) {
		log_debug("[SKIP LIST] lookup_elem: next is NULL at level %d, dropping down", ctx->level);
		--ctx->level;
		return 0; // Continue
	}
	skip_key_type_t __arena *next_key = &(next->key);
	cast_kern(next_key);
	int cmp = skip_key_cmp(next_key, ctx->key);
	log_debug("[SKIP LIST] lookup_elem: comparing with key %u, cmp result %d", next_key->key, cmp);
	cast_kern(next);
	if (cmp == 0) {
		log_debug("[SKIP LIST] lookup_elem: found key %u at level %d after %u iterations", ctx->key->key, ctx->level, ctx->cnt);
		ctx->result = next;
		return 1; // Stop iteration
	} else if (cmp > 0) {
		log_debug("[SKIP LIST] lookup_elem: key %u > target, dropping down from level %d", next_key->key, ctx->level);
		--ctx->level;
		return 0; // Continue
	} else {
		log_debug("[SKIP LIST] lookup_elem: key %u < target, moving forward at level %d", next_key->key, ctx->level);
		ctx->curr = next;
		return 0; // Continue
	}
}

static inline int init_new_entry(sl_entry *entry, skip_key_type_t *key, skip_value_type_t *value)
{
	if (!entry || !key || !value) {
		log_debug("[SKIP LIST] init_new_entry: invalid parameters");
		return -1;
	}
	cast_kern(entry);
	__builtin_memset(entry, 0, sizeof(sl_entry));

	int new_height = bpf_grand();
	log_debug("[SKIP LIST] init_new_entry: new entry random height %d", new_height);
	cast_kern(entry);
	entry->height = new_height;
	log_debug("[SKIP LIST] init_new_entry: allocated new entry with height %d", entry->height);
	
	void __arena *key_ptr = &entry->key;
	void __arena *value_ptr = &entry->value;
	cast_kern(key_ptr);
	cast_kern(value_ptr);
	__builtin_memcpy(key_ptr, key, sizeof(skip_key_type_t));
	__builtin_memcpy(value_ptr, value, sizeof(skip_value_type_t));
	log_debug("[SKIP LIST] init_new_entry: initialized new entry with key %u, value %lu", entry->key.key, entry->value.data);
	return 0;
}

static inline sl_entry *skip_list_lookup_elem(sl_entry *head, skip_key_type_t *key)
{
	cast_kern(head);
	struct lookup_ctx ctx = {
		.curr = head,
		.key = key,
		.level = head->height - 1,
		.cnt = 0,
		.result = NULL
	};

	log_debug("[SKIP LIST] lookup_elem: searching for key %u, start level %d", key->key, ctx.level);

	bpf_loop(MAX_SEARCH_DEPTH, lookup_callback, &ctx, 0);

	if (ctx.result == NULL) {
		log_debug("[SKIP LIST] lookup_elem: key %u not found after %u iterations, final level %d", key->key, ctx.cnt, ctx.level);
	}

	return ctx.result;
}

struct update_search_ctx {
	sl_entry *prev[MAX_SKIPLIST_HEIGHT];
	sl_entry *curr;
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
	if (ctx->curr == NULL || ctx->level < 0 || ctx->cnt >= MAX_SEARCH_DEPTH) {
		return 1; // Stop iteration
	}

	ctx->prev[(ctx->level) & (MAX_SKIPLIST_HEIGHT - 1)] = ctx->curr;
	sl_entry *next = ptr_get_next(ctx->curr, ctx->level);
	if (next == NULL) {
		log_debug("[SKIP LIST] update_elem: next is NULL at level %d, dropping down", ctx->level);
		--ctx->level;
		return 0; // Continue
	}
	skip_key_type_t *next_key = &next->key;
	int cmp = skip_key_cmp(next_key, ctx->key);
	if (cmp == 0) {
		log_debug("[SKIP LIST] update_elem: found existing key %u at level %d, updating value from %lu to %lu",
			  ctx->key->key, ctx->level, next->value.data, ctx->value->data);
		next->value = *ctx->value;
		ctx->found = 1;
		return 1; // Stop iteration
	} else if (cmp > 0) {
		log_debug("[SKIP LIST] update_elem: key %u > target, dropping down from level %d", next_key->key, ctx->level);
		--ctx->level;
		return 0; // Continue
	} else {
		log_debug("[SKIP LIST] update_elem: key %u < target, moving forward at level %d", next_key->key, ctx->level);
		ctx->curr = next;
		return 0; // Continue
	}
}


static inline long skip_list_update_elem(sl_entry *head, skip_key_type_t *key, skip_value_type_t *value)
{
	cast_kern(head);
	struct update_search_ctx ctx = {
		.curr = head,
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
    sl_entry *new_entry = bpf_alloc(sizeof(sl_entry));
	if (new_entry == NULL) {
        log_error("[SKIP LIST] bpf_alloc failed");
        return -1;
    }

	if (init_new_entry(new_entry, key, value) < 0) {
		log_error("[SKIP LIST] init_new_entry failed");
		bpf_free(new_entry);
		return -1;
	}

	log_debug("[SKIP LIST] update_elem: linking new entry at all levels");
	// Link the new entry at all levels using a normal for loop
	#pragma unroll 1
	for (int i = 0; i < MAX_SKIPLIST_HEIGHT; i++) {
		cast_kern(new_entry);
		if (i >= new_entry->height) {
			new_entry->next[i] = NULL;
			log_debug("[SKIP LIST] update_elem: level %d above height, setting next to NULL", i);
		} else {
			sl_entry *prev_node = ctx.prev[i];
			cast_kern(new_entry);
			cast_kern(prev_node);
			connected_prev_next(new_entry, i, prev_node->next[i]);
			cast_kern(prev_node);
			connected_prev_next(prev_node, i, new_entry);			
		}
	}
	return 0;
}