#ifndef __CUCKOO_HASH_H__
#define __CUCKOO_HASH_H__

#include "../vmlinux.h"
#include "../common.h"
#include "../crc.h"
#include "simple_ringbuf.h"
 
// Constants that can be redefined in different files
// #ifndef CUCKOO_FORCE_COMPARISON_COUNT
// #define CUCKOO_FORCE_COMPARISON_COUNT 1
// #endif

#ifndef CUCKOO_HASH_LOOKUP_ONLY
#define CUCKOO_HASH_LOOKUP_ONLY
#endif

#ifndef CUCKOO_HASH_BUCKET_ENTRIES
#define CUCKOO_HASH_BUCKET_ENTRIES 16
#endif
#define CUCKOO_IS_POWER_OF_2(n) ((n) && !(((n)-1) & (n)))
#if !CUCKOO_IS_POWER_OF_2(CUCKOO_HASH_BUCKET_ENTRIES)
#error CUCKOO_HASH_BUCKET_ENTRIES must be a power of 2
#endif
#define CUCKOO_HASH_EMPTY_SLOT 0
#define CUCKOO_HASH_SEED 0xdeadbeef

#ifndef CUCKOO_HASH_ENTRIES
#define CUCKOO_HASH_ENTRIES 4096
#endif 

#define CUCKOO_HASH_KEY_SLOTS (CUCKOO_HASH_ENTRIES + 1)
#if !CUCKOO_IS_POWER_OF_2(CUCKOO_HASH_ENTRIES)
#error CUCKOO_HASH_ENTRIES must be a power of 2
#endif
#define CUCKOO_HASH_NUM_BUCKETS (CUCKOO_HASH_ENTRIES / CUCKOO_HASH_BUCKET_ENTRIES)
#define CUCKOO_HASH_BUCKET_BITMASK (CUCKOO_HASH_NUM_BUCKETS - 1)
#define CUCKOO_HASH_GET_BUCKET(h, idx) \
	INDEX_WITH_BOUND((h)->buckets, (idx), CUCKOO_HASH_NUM_BUCKETS)

#if defined(CUCKOO_HASH_DEBUG)
#define RETURN_IF_TRUE(cond, retval)   \
	do {                           \
		if (cond)              \
			return retval; \
	} while (0)
#else
#define RETURN_IF_TRUE(cond, retval)
#endif

#ifndef CUCKOO_HASH_KEY_SLOTS_SHIFT
#define CUCKOO_HASH_KEY_SLOTS_SHIFT 12
#endif
#if (1 << CUCKOO_HASH_KEY_SLOTS_SHIFT) != CUCKOO_HASH_ENTRIES
#error CUCKOO_HASH_KEY_SLOTS_SHIFT must be consistent with CUCKOO_HASH_ENTRIES
#endif

#ifndef CUCKOO_HASH_BFS_QUEUE_SHIFT
#define CUCKOO_HASH_BFS_QUEUE_SHIFT 10
#endif
#define CUCKOO_HASH_BFS_QUEUE_NODES \
	SHIFT_TO_SIZE(CUCKOO_HASH_BFS_QUEUE_SHIFT + 1)
#define CUCKOO_HASH_GET_BFS_QUEUE_NODE(q, idx)        \
	INDEX_WITH_BOUND((q)->bfs_queue_nodes, (idx), \
			 CUCKOO_HASH_BFS_QUEUE_NODES)
#define CUCKOO_HASH_GET_BFS_QUEUE_HEAD_OR_TAIL(h, node_idx_ptr, prod_or_cons) \
	({                                                                    \
		(node_idx_ptr) =                                              \
			cuckoo_hash_bfs_queue__simple_rbuf_##prod_or_cons(    \
				&(h)->bfs_queue);                             \
		if ((node_idx_ptr) == NULL) {                                 \
			cuckoo_log(error,                                     \
				   "cannot get bfs queue " #prod_or_cons);    \
			return -EINVAL;                                       \
		}                                                             \
		CUCKOO_HASH_GET_BFS_QUEUE_NODE((h), *(node_idx_ptr));         \
	})
#define CUCKOO_HASH_GET_BFS_QUEUE_HEAD(h, node_idx_ptr) \
	CUCKOO_HASH_GET_BFS_QUEUE_HEAD_OR_TAIL(h, node_idx_ptr, prod)
#define CUCKOO_HASH_GET_BFS_QUEUE_TAIL(h, node_idx_ptr) \
	CUCKOO_HASH_GET_BFS_QUEUE_HEAD_OR_TAIL(h, node_idx_ptr, cons)

#ifdef USE_LOOKUP_ONLY
#define CUCKOO_HASH_LOOKUP_ONLY
#endif

/* Data types */
struct pkt_5tuple_with_pad {
	struct pkt_5tuple pkt;
	u8 __pad[3];
} __attribute__((packed));

typedef struct pkt_5tuple_with_pad cuckoo_hash_key_t;
typedef u16 __cuckoo_hash_key_idx_t;
typedef u32 cuckoo_hash_value_t;
typedef u32 cuckoo_hash_sig_t;

#define CUCKOO_HASH_KEY_SIZE sizeof(cuckoo_hash_key_t)
#define CUCKOO_HASH_VALUE_SIZE sizeof(cuckoo_hash_value_t)

#define cuckoo_log(level, fmt, ...)                                \
	log_##level(" cuckoo_hash (ebpf): " fmt " (%s @ line %d)", \
		    ##__VA_ARGS__, __func__, __LINE__)

/* Forward declarations for simple ringbuf */
DECLARE_SIMPLE_RINGBUF(cuckoo_hash_free_slots, u32,
		       CUCKOO_HASH_KEY_SLOTS_SHIFT);
DECLARE_SIMPLE_RINGBUF(cuckoo_hash_bfs_queue, u32,
		       CUCKOO_HASH_BFS_QUEUE_SHIFT);

struct __cuckoo_hash_key {
	cuckoo_hash_value_t value;
	cuckoo_hash_key_t key;
};

struct __cuckoo_hash_bucket {
	u16 sig_current[CUCKOO_HASH_BUCKET_ENTRIES];
	__cuckoo_hash_key_idx_t key_idx[CUCKOO_HASH_BUCKET_ENTRIES];
};

struct cuckoo_hash {
	struct simple_rbuf__cuckoo_hash_free_slots free_slot_list;
	struct __cuckoo_hash_key key_store[CUCKOO_HASH_KEY_SLOTS];
	struct __cuckoo_hash_bucket buckets[CUCKOO_HASH_NUM_BUCKETS];
	u32 initialized : 1;
};

struct __cuckoo_hash_bfs_queue_node {
	u32 bkt_idx;
	u32 prev_node_idx;
	int prev_slot;
};

struct cuckoo_hash_parameters {
	struct cuckoo_hash *hash_table;
	struct __cuckoo_hash_bfs_queue *bfs_queue;
};

struct __cuckoo_hash_bfs_queue {
	struct simple_rbuf__cuckoo_hash_bfs_queue bfs_queue;
	struct __cuckoo_hash_bfs_queue_node
		bfs_queue_nodes[CUCKOO_HASH_BFS_QUEUE_NODES];
};

/* Helper macros */
#define INDEX_WITH_BOUND(arr, idx, size)                                   \
	({                                                                 \
		if ((idx) >= (size)) {                                     \
			cuckoo_log(error, "idx %d >= size %d", idx, size); \
			return -EINVAL;                                    \
		}                                                          \
		(arr) + (idx);                                             \
	})

#define SIMPLE_RINGBUF_CLEAR(ringbuf) \
	do {                          \
		(ringbuf)->cons = 0;  \
		(ringbuf)->prod = 0;  \
	} while (0)

#define inline inline __attribute__((always_inline))

/* Function implementations */
static inline void __cuckoo_hash_enqueue_slot_back(struct cuckoo_hash *h,
						   u32 slot_id)
{
	struct simple_rbuf__cuckoo_hash_free_slots *free_slot_list;
	u32 *slot;

	free_slot_list = &h->free_slot_list;
	slot = cuckoo_hash_free_slots__simple_rbuf_prod(free_slot_list);
	if (slot == NULL) {
		cuckoo_log(error, "cannot enqueue slot %d", slot_id);
		return;
	}
	*slot = slot_id;
	cuckoo_hash_free_slots__simple_rbuf_submit(free_slot_list);
}

static inline struct cuckoo_hash *
get_cuckoo_hash(void *cuckoo_hash_map)
{
	int zero = 0, i;
	struct cuckoo_hash *h;

	cuckoo_log(debug, "get_cuckoo_hash: called with map=%p", cuckoo_hash_map);

	if (cuckoo_hash_map == NULL) {
		cuckoo_log(error, "invalid cuckoo_hash_map parameter");
		return NULL;
	}

	h = (struct cuckoo_hash*) bpf_map_lookup_elem(cuckoo_hash_map, &zero);
	if (h == NULL) {
		cuckoo_log(error, "cannot find cuckoo hash map");
		return NULL;
	}

	cuckoo_log(debug, "get_cuckoo_hash: found hash table at %p, initialized=%d", h, h->initialized);

	if (!h->initialized) {
		cuckoo_log(debug, "get_cuckoo_hash: initializing hash table, key_slots=%d", CUCKOO_HASH_KEY_SLOTS);
		for (i = 1; i < CUCKOO_HASH_KEY_SLOTS; i++) {
			__cuckoo_hash_enqueue_slot_back(h, i);
		}
		h->initialized = 1;
		cuckoo_log(debug, "get_cuckoo_hash: hash table initialization completed");
	}

	return h;
}

/* Wrapper function to match C implementation parameter order */
static inline u32 __cuckoo_hash_crc32c(u32 crc, const void *data, size_t length)
{
	return crc32c(data, (u32)length, crc);
}

static inline cuckoo_hash_sig_t __cuckoo_hash_hash(struct cuckoo_hash *h,
						   const cuckoo_hash_key_t *key)
{
	cuckoo_hash_sig_t hash = __cuckoo_hash_crc32c(CUCKOO_HASH_SEED, key, CUCKOO_HASH_KEY_SIZE);
	cuckoo_log(debug, "__cuckoo_hash_hash: key=0x%08x... hash=0x%08x", *((u32*)key), hash);
	return hash;
}

static inline u16 __cuckoo_hash_get_short_sig(const cuckoo_hash_sig_t hash)
{
	return hash >> 16;
}

static inline u32
__cuckoo_hash_get_prim_bucket_index(struct cuckoo_hash *h,
				    const cuckoo_hash_sig_t hash)
{
	return hash & CUCKOO_HASH_BUCKET_BITMASK;
}

static inline u32 __cuckoo_hash_get_alt_bucket_index(struct cuckoo_hash *h,
							  u32 cur_bkt_idx,
							  u16 sig)
{
	return (cur_bkt_idx ^ sig) & CUCKOO_HASH_BUCKET_BITMASK;
}

static inline int __cuckoo_hash_memcmp(const void *s1, const void *s2, size_t n)
{
	const uint8_t *p1 = s1, *p2 = s2;
	int ret = 0;

	while (n--) {
		if ((ret = *p1++ - *p2++) != 0)
			break;
	}
	return ret;
}

static inline int __cuckoo_hash_cmp_eq(const cuckoo_hash_key_t *key1,
				       const cuckoo_hash_key_t *key2,
				       struct cuckoo_hash *h)
{
	return __cuckoo_hash_memcmp(key1, key2, sizeof(*key1));
}

static inline int32_t
__cuckoo_hash_search_and_update(struct cuckoo_hash *h,
				const cuckoo_hash_value_t *data,
				const cuckoo_hash_key_t *key,
				struct __cuckoo_hash_bucket *bkt, u16 sig)
{
	u32 i;
	__cuckoo_hash_key_idx_t key_idx;
	struct __cuckoo_hash_key *k, *keys = h->key_store;

	for (i = 0; i < CUCKOO_HASH_BUCKET_ENTRIES; i++) {
		if (bkt->sig_current[i] == sig) {
			key_idx = bkt->key_idx[i];
			if (key_idx >= CUCKOO_HASH_KEY_SLOTS) {
				cuckoo_log(
					error,
					"invalid key index %d > CUCKOO_HASH_KEY_SLOTS %d",
					key_idx, CUCKOO_HASH_KEY_SLOTS);
				return -EINVAL;
			}

			k = keys + key_idx;
			if (__cuckoo_hash_cmp_eq(key, &k->key, h) == 0) {
				__builtin_memcpy(&k->value, data,
						 CUCKOO_HASH_VALUE_SIZE);
				return bkt->key_idx[i] - 1;
			}
		}
	}
	return -1;
}

static inline u32 __cuckoo_hash_alloc_slot(struct cuckoo_hash *h)
{
	struct simple_rbuf__cuckoo_hash_free_slots *free_slot_list;
	u32 *slot;

	free_slot_list = &h->free_slot_list;
	slot = cuckoo_hash_free_slots__simple_rbuf_cons(free_slot_list);
	if (slot == NULL) {
		cuckoo_log(warn, "cannot allocate slot");
		return CUCKOO_HASH_EMPTY_SLOT;
	}
	cuckoo_hash_free_slots__simple_rbuf_release(free_slot_list);

	return *slot;
}

static inline int32_t __cuckoo_hash_cuckoo_insert_mw(
	struct cuckoo_hash *h, struct __cuckoo_hash_bucket *prim_bkt,
	struct __cuckoo_hash_bucket *sec_bkt,
	const struct __cuckoo_hash_key *key, cuckoo_hash_value_t *data,
	u16 sig, u32 new_idx, int32_t *ret_val)
{
	unsigned int i;

	for (i = 0; i < CUCKOO_HASH_BUCKET_ENTRIES; i++) {
		if (likely(prim_bkt->key_idx[i] == CUCKOO_HASH_EMPTY_SLOT)) {
			prim_bkt->sig_current[i] = sig;
			prim_bkt->key_idx[i] = new_idx;
			break;
		}
	}

	if (i != CUCKOO_HASH_BUCKET_ENTRIES) {
		return 0;
	}

	return -1;
}

static inline int __cuckoo_hash_cuckoo_move_insert_mw(
	struct cuckoo_hash_parameters *params, struct __cuckoo_hash_bucket *bkt,
	struct __cuckoo_hash_bucket *alt_bkt,
	const struct __cuckoo_hash_key *key, cuckoo_hash_value_t *data,
	struct __cuckoo_hash_bfs_queue *q, u32 leaf_node_idx,
	u32 leaf_slot, u16 sig, u32 new_idx, int32_t *ret_val)
{
	u32 prev_alt_bkt_idx;
	struct __cuckoo_hash_bfs_queue_node *prev_node,
		*curr_node = CUCKOO_HASH_GET_BFS_QUEUE_NODE(q, leaf_node_idx);
	struct __cuckoo_hash_bucket *prev_bkt,
		*curr_bkt = CUCKOO_HASH_GET_BUCKET(params->hash_table, curr_node->bkt_idx);
	u32 prev_slot, curr_slot = leaf_slot;

	while (likely(curr_node->prev_node_idx != -1)) {
		prev_node = CUCKOO_HASH_GET_BFS_QUEUE_NODE(
			q, curr_node->prev_node_idx);
		prev_bkt = CUCKOO_HASH_GET_BUCKET(params->hash_table, prev_node->bkt_idx);
		prev_slot = curr_node->prev_slot;

		prev_alt_bkt_idx = __cuckoo_hash_get_alt_bucket_index(
			params->hash_table, prev_node->bkt_idx,
			prev_bkt->sig_current[prev_slot]);

		if (unlikely(&params->hash_table->buckets[prev_alt_bkt_idx] != curr_bkt)) {
			curr_bkt->key_idx[curr_slot] = CUCKOO_HASH_EMPTY_SLOT;
			return -1;
		}

		curr_bkt->sig_current[curr_slot] =
			prev_bkt->sig_current[prev_slot];
		curr_bkt->key_idx[curr_slot] = prev_bkt->key_idx[prev_slot];

		curr_slot = prev_slot;
		curr_node = prev_node;
		curr_bkt = CUCKOO_HASH_GET_BUCKET(params->hash_table, curr_node->bkt_idx);
	}

	curr_bkt->sig_current[curr_slot] = sig;
	curr_bkt->key_idx[curr_slot] = new_idx;

	return 0;
}

static inline int __cuckoo_hash_cuckoo_make_space_mw(
	struct cuckoo_hash_parameters *params, u32 bkt_idx, u32 sec_bkt_idx,
	const struct __cuckoo_hash_key *key, cuckoo_hash_value_t *data,
	u16 sig, u32 new_idx, int32_t *ret_val)
{
	unsigned int i;
	struct __cuckoo_hash_bfs_queue *q;
	struct simple_rbuf__cuckoo_hash_bfs_queue *queue;
	struct __cuckoo_hash_bfs_queue_node *tail, *head;
	struct __cuckoo_hash_bucket *bkt, *sec_bkt, *curr_bkt, *alt_bkt;
	u32 cur_bkt_idx, alt_bkt_idx, *tail_node_idx, *head_node_idx;

	if (params == NULL || params->hash_table == NULL || params->bfs_queue == NULL) {
		cuckoo_log(error, "invalid parameters");
		return -EINVAL;
	}
	q = params->bfs_queue;

	queue = &q->bfs_queue;

	bkt = CUCKOO_HASH_GET_BUCKET(params->hash_table, bkt_idx);
	sec_bkt = CUCKOO_HASH_GET_BUCKET(params->hash_table, sec_bkt_idx);

	SIMPLE_RINGBUF_CLEAR(queue);
	tail = CUCKOO_HASH_GET_BFS_QUEUE_TAIL(q, tail_node_idx);
	tail->bkt_idx = bkt_idx;
	tail->prev_node_idx = -1;
	tail->prev_slot = -1;

	while (likely(!cuckoo_hash_bfs_queue__simple_rbuf_empty(queue) &&
		      !cuckoo_hash_bfs_queue__simple_rbuf_full(queue))) {
		tail = CUCKOO_HASH_GET_BFS_QUEUE_TAIL(q, tail_node_idx);
		cur_bkt_idx = tail->bkt_idx;
		curr_bkt = CUCKOO_HASH_GET_BUCKET(params->hash_table, cur_bkt_idx);

		for (i = 0; i < CUCKOO_HASH_BUCKET_ENTRIES; i++) {
			if (curr_bkt->key_idx[i] == CUCKOO_HASH_EMPTY_SLOT) {
				int32_t ret =
					__cuckoo_hash_cuckoo_move_insert_mw(
						params, bkt, sec_bkt, key, data, q,
						*tail_node_idx, i, sig, new_idx,
						ret_val);
				if (likely(ret != -1))
					return ret;
			}

			alt_bkt_idx = __cuckoo_hash_get_alt_bucket_index(
				params->hash_table, cur_bkt_idx, curr_bkt->sig_current[i]);
			alt_bkt = CUCKOO_HASH_GET_BUCKET(params->hash_table, alt_bkt_idx);

			head = CUCKOO_HASH_GET_BFS_QUEUE_HEAD(q, head_node_idx);
			head->bkt_idx = alt_bkt_idx;
			head->prev_node_idx = *tail_node_idx;
			head->prev_slot = i;
			cuckoo_hash_bfs_queue__simple_rbuf_submit(queue);
		}
		cuckoo_hash_bfs_queue__simple_rbuf_release(queue);
	}

	return -ENOSPC;
}

static inline int32_t __cuckoo_hash_add_key_with_hash(
	struct cuckoo_hash_parameters *params, const cuckoo_hash_key_t *key,
	cuckoo_hash_sig_t sig, cuckoo_hash_value_t *data)
{
	u16 short_sig;
	u32 prim_bucket_idx, sec_bucket_idx;
	struct __cuckoo_hash_bucket *prim_bkt, *sec_bkt;
	struct __cuckoo_hash_key *new_k, *keys = params->hash_table->key_store;
	u32 slot_id;
	int ret;
	int32_t ret_val;

	short_sig = __cuckoo_hash_get_short_sig(sig);
	prim_bucket_idx = __cuckoo_hash_get_prim_bucket_index(params->hash_table, sig);
	sec_bucket_idx =
		__cuckoo_hash_get_alt_bucket_index(params->hash_table, prim_bucket_idx, sig);
	prim_bkt = &params->hash_table->buckets[prim_bucket_idx];
	sec_bkt = &params->hash_table->buckets[sec_bucket_idx];

	ret = __cuckoo_hash_search_and_update(params->hash_table, data, key, prim_bkt,
					      short_sig);
	if (ret != -1) {
		return ret;
	}

	ret = __cuckoo_hash_search_and_update(params->hash_table, data, key, sec_bkt, short_sig);
	if (ret != -1) {
		return ret;
	}

	slot_id = __cuckoo_hash_alloc_slot(params->hash_table);
	if (slot_id == CUCKOO_HASH_EMPTY_SLOT) {
		return -ENOSPC;
	}

	if (slot_id >= CUCKOO_HASH_KEY_SLOTS) {
		cuckoo_log(error,
			   "invalid key index %d > CUCKOO_HASH_KEY_SLOTS %d",
			   slot_id, CUCKOO_HASH_KEY_SLOTS);
		return -EINVAL;
	}
	new_k = keys + slot_id;
	__builtin_memcpy(&new_k->value, data, CUCKOO_HASH_VALUE_SIZE);
	__builtin_memcpy(&new_k->key, key, CUCKOO_HASH_KEY_SIZE);

	ret = __cuckoo_hash_cuckoo_insert_mw(params->hash_table, prim_bkt, sec_bkt,
					     (struct __cuckoo_hash_key *)key,
					     data, short_sig, slot_id,
					     &ret_val);
	if (ret == 0) {
		return slot_id - 1;
	} else if (ret == 1) {
		__cuckoo_hash_enqueue_slot_back(params->hash_table, slot_id);
		return ret_val;
	}

	ret = __cuckoo_hash_cuckoo_make_space_mw(
		params, prim_bucket_idx, sec_bucket_idx,
		(struct __cuckoo_hash_key *)key, data, short_sig, slot_id,
		&ret_val);
	if (ret == 0) {
		return slot_id - 1;
	} else if (ret == 1) {
		__cuckoo_hash_enqueue_slot_back(params->hash_table, slot_id);
		return ret_val;
	}

	ret = __cuckoo_hash_cuckoo_make_space_mw(
		params, sec_bucket_idx, prim_bucket_idx,
		(struct __cuckoo_hash_key *)key, data, short_sig, slot_id,
		&ret_val);
	if (ret == 0) {
		return slot_id - 1;
	} else if (ret == 1) {
		__cuckoo_hash_enqueue_slot_back(params->hash_table, slot_id);
		return ret_val;
	}

	__cuckoo_hash_enqueue_slot_back(params->hash_table, slot_id);
	return ret;
}

static inline int cuckoo_hash_update_elem(struct cuckoo_hash_parameters *params,
					  cuckoo_hash_key_t *key,
					  cuckoo_hash_value_t *value)
{
	int ret;

	RETURN_IF_TRUE(((params == NULL) || (params->hash_table == NULL) || (key == NULL)), -EINVAL);

	ret = __cuckoo_hash_add_key_with_hash(
		params, key, __cuckoo_hash_hash(params->hash_table, key), value);
	if (ret >= 0) {
		return 0;
	} else {
		return ret;
	}
}

static int32_t __cuckoo_hash_search_one_bucket(struct cuckoo_hash *h,
					       const cuckoo_hash_key_t *key,
					       u16 sig,
					       cuckoo_hash_value_t **data,
					       struct __cuckoo_hash_bucket *bkt)
{
	u32 i;
	__cuckoo_hash_key_idx_t key_idx;
	struct __cuckoo_hash_key *k = NULL, *keys = h->key_store;

	cuckoo_log(debug, "__cuckoo_hash_search_one_bucket: searching bucket with sig=0x%04x", sig);

#if defined(CUCKOO_FORCE_COMPARISON_COUNT) && CUCKOO_FORCE_COMPARISON_COUNT > 0
#if CUCKOO_FORCE_COMPARISON_COUNT > 16
#error CUCKOO_FORCE_COMPARISON_COUNT must be <= 16
#endif
	for (i = 0; i < CUCKOO_FORCE_COMPARISON_COUNT; i++) {
		key_idx = bkt->key_idx[i];

		if (bkt->sig_current[i] == sig &&
		    key_idx != CUCKOO_HASH_EMPTY_SLOT) {
			if (key_idx >= CUCKOO_HASH_KEY_SLOTS) {
				cuckoo_log(
					error,
					"invalid key index %d > CUCKOO_HASH_KEY_SLOTS %d",
					bkt->key_idx[i], CUCKOO_HASH_KEY_SLOTS);
				return -EINVAL;
			}

			k = keys + key_idx;
		}
	}
	if (k == NULL) {
		k = keys;
	}
	if (__cuckoo_hash_cmp_eq(key, &k->key, h) == 0) {
		*data = &k->value;
		cuckoo_log(debug, "found key at entry %d, key index %d", i,
			   bkt->key_idx[i] - 1);
		return bkt->key_idx[i] - 1;
	} else {
		*data = &k->value;
		return 0;
	}
#else
	for (i = 0; i < CUCKOO_HASH_BUCKET_ENTRIES; i++) {
		key_idx = bkt->key_idx[i];

		if (bkt->sig_current[i] == sig &&
		    key_idx != CUCKOO_HASH_EMPTY_SLOT) {
			if (key_idx >= CUCKOO_HASH_KEY_SLOTS) {
				cuckoo_log(
					error,
					"invalid key index %d > CUCKOO_HASH_KEY_SLOTS %d",
					bkt->key_idx[i], CUCKOO_HASH_KEY_SLOTS);
				return -EINVAL;
			}

			k = keys + key_idx;
			if (__cuckoo_hash_cmp_eq(key, &k->key, h) == 0) {
				*data = &k->value;
				cuckoo_log(
					debug,
					"found key at entry %d, key index %d",
					i, bkt->key_idx[i] - 1);
				return bkt->key_idx[i] - 1;
			}
		}
	}
#endif
	return -1;
}

static inline int32_t __cuckoo_hash_lookup_with_hash(
	struct cuckoo_hash *h, const cuckoo_hash_key_t *key,
	cuckoo_hash_sig_t sig, cuckoo_hash_value_t **data)
{
	u32 prim_bucket_idx, sec_bucket_idx;
	struct __cuckoo_hash_bucket *bkt, *cur_bkt;
	int ret, i;
	u16 short_sig;

	short_sig = __cuckoo_hash_get_short_sig(sig);
	prim_bucket_idx = __cuckoo_hash_get_prim_bucket_index(h, sig);
	sec_bucket_idx = __cuckoo_hash_get_alt_bucket_index(h, prim_bucket_idx,
							    short_sig);

	cuckoo_log(debug, "__cuckoo_hash_lookup_with_hash: hash=0x%08x, short_sig=0x%04x, prim_bkt=%d, sec_bkt=%d",
		   sig, short_sig, prim_bucket_idx, sec_bucket_idx);

	bkt = &h->buckets[prim_bucket_idx];
	cuckoo_log(debug, "__cuckoo_hash_lookup_with_hash: searching primary bucket %d", prim_bucket_idx);

	ret = __cuckoo_hash_search_one_bucket(h, key, short_sig, data, bkt);
	if (ret != -1) {
		cuckoo_log(debug, "__cuckoo_hash_lookup_with_hash: found in primary bucket");
		return ret;
	}

	bkt = &h->buckets[sec_bucket_idx];
	cuckoo_log(debug, "__cuckoo_hash_lookup_with_hash: searching secondary bucket %d", sec_bucket_idx);

	ret = __cuckoo_hash_search_one_bucket(h, key, short_sig, data, bkt);
	if (ret != -1) {
		cuckoo_log(debug, "__cuckoo_hash_lookup_with_hash: found in secondary bucket");
		return ret;
	}

	cuckoo_log(debug, "__cuckoo_hash_lookup_with_hash: key not found in either bucket");
	return -ENOENT;
}

static inline int32_t cuckoo_hash_lookup_elem(struct cuckoo_hash_parameters *params,
					      const cuckoo_hash_key_t *key,
					      cuckoo_hash_value_t **data)
{
	int32_t ret;
	cuckoo_hash_sig_t hash;

	RETURN_IF_TRUE(((params == NULL) || (params->hash_table == NULL) || (key == NULL)), -EINVAL);

	hash = __cuckoo_hash_hash(params->hash_table, key);
	cuckoo_log(debug, "cuckoo_hash_lookup_elem: key=0x%08x... hash=0x%08x", *((u32*)key), hash);

	ret = __cuckoo_hash_lookup_with_hash(params->hash_table, key, hash, data);
	if (ret >= 0) {
		cuckoo_log(debug, "cuckoo_hash_lookup_elem: found key at slot %d, value=%d", ret, *data ? **data : 0);
		return 0;
	} else {
		cuckoo_log(debug, "cuckoo_hash_lookup_elem: key not found, ret=%d", ret);
		return ret;
	}
}

#endif /* __CUCKOO_HASH_H__ */