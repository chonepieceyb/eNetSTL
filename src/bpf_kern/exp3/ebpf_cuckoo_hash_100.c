#include "../vmlinux.h"
#include "../common.h"
#include "../crc.h"

#include "simple_ringbuf.h"

#define CUCKOO_FORCE_COMPARISON_COUNT 16
#define CUCKOO_HASH_LOOKUP_ONLY

#define INDEX_WITH_BOUND(arr, idx, size)                                   \
	({                                                                 \
		if ((idx) >= (size)) {                                     \
			cuckoo_log(error, "idx %d >= size %d", idx, size); \
			return -EINVAL;                                    \
		}                                                          \
		(arr) + (idx);                                             \
	})

// Due to this macro, we should always clear the value returned by xxx__simple_rbuf_prod before use.
#define SIMPLE_RINGBUF_CLEAR(ringbuf) \
	do {                          \
		(ringbuf)->cons = 0;  \
		(ringbuf)->prod = 0;  \
	} while (0)

#define inline inline __attribute__((always_inline))

#define CUCKOO_HASH_BUCKET_ENTRIES 16
#define CUCKOO_IS_POWER_OF_2(n) ((n) && !(((n)-1) & (n)))
#if !CUCKOO_IS_POWER_OF_2(CUCKOO_HASH_BUCKET_ENTRIES)
#error CUCKOO_HASH_BUCKET_ENTRIES must be a power of 2
#endif
#define CUCKOO_HASH_EMPTY_SLOT 0
#define CUCKOO_HASH_SEED 0xdeadbeef
// h->entries in DPDK; we added an extra constraint that it must be a power of 2
#define CUCKOO_HASH_ENTRIES 512
#define CUCKOO_HASH_KEY_SLOTS (CUCKOO_HASH_ENTRIES + 1)
#if !CUCKOO_IS_POWER_OF_2(CUCKOO_HASH_ENTRIES)
#error CUCKOO_HASH_ENTRIES must be a power of 2
#endif
// h->num_buckets in DPDK
#define CUCKOO_HASH_NUM_BUCKETS \
	(CUCKOO_HASH_ENTRIES / CUCKOO_HASH_BUCKET_ENTRIES)
// h->bucket_bitmask in DPDK
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

// This needs to be consistent with CUCKOO_HASH_ENTRIES
#define CUCKOO_HASH_KEY_SLOTS_SHIFT 9
#if (1 << CUCKOO_HASH_KEY_SLOTS_SHIFT) != CUCKOO_HASH_ENTRIES
#error CUCKOO_HASH_KEY_SLOTS_SHIFT must be consistent with CUCKOO_HASH_ENTRIES
#endif

#define CUCKOO_HASH_BFS_QUEUE_SHIFT 10
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

struct __cuckoo_hash_bfs_queue_node {
	uint32_t bkt_idx;

	uint32_t prev_node_idx; /* Parent(bucket) in search path */
	int prev_slot; /* Parent(slot) in search path */
};

DECLARE_SIMPLE_RINGBUF(cuckoo_hash_free_slots, uint32_t,
		       CUCKOO_HASH_KEY_SLOTS_SHIFT);
DECLARE_SIMPLE_RINGBUF(cuckoo_hash_bfs_queue, uint32_t,
		       CUCKOO_HASH_BFS_QUEUE_SHIFT);

struct cuckoo_hash_parameters {};

struct pkt_5tuple_with_pad {
	struct pkt_5tuple pkt;
	uint8_t __pad[3];
} __attribute__((packed));

typedef struct pkt_5tuple_with_pad cuckoo_hash_key_t;
typedef uint16_t __cuckoo_hash_key_idx_t;
typedef uint32_t cuckoo_hash_value_t;
typedef uint32_t cuckoo_hash_sig_t;

#define CUCKOO_HASH_KEY_SIZE sizeof(cuckoo_hash_key_t)
#define CUCKOO_HASH_VALUE_SIZE sizeof(cuckoo_hash_value_t)

#define cuckoo_log(level, fmt, ...)                                \
	log_##level(" cuckoo_hash (ebpf): " fmt " (%s @ line %d)", \
		    ##__VA_ARGS__, __func__, __LINE__)

struct __cuckoo_hash_key {
	cuckoo_hash_value_t value;
	cuckoo_hash_key_t key;
};

struct __cuckoo_hash_bucket {
	uint16_t sig_current[CUCKOO_HASH_BUCKET_ENTRIES];
	__cuckoo_hash_key_idx_t key_idx[CUCKOO_HASH_BUCKET_ENTRIES];
};

struct cuckoo_hash {
	struct simple_rbuf__cuckoo_hash_free_slots free_slot_list;
	struct __cuckoo_hash_key key_store[CUCKOO_HASH_KEY_SLOTS];
	struct __cuckoo_hash_bucket buckets[CUCKOO_HASH_NUM_BUCKETS];

	uint32_t initialized : 1;
};

struct __cuckoo_hash_bfs_queue {
	struct simple_rbuf__cuckoo_hash_bfs_queue bfs_queue;
	struct __cuckoo_hash_bfs_queue_node
		bfs_queue_nodes[CUCKOO_HASH_BFS_QUEUE_NODES];
};

char LICENSE[] SEC("license") = "GPL";
uint32_t dummy;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct cuckoo_hash);
	/* Not using prefill for now */
	/* __uint(pinning, 1); */
} cuckoo_hash_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct __cuckoo_hash_bfs_queue);
} __cuckoo_hash_bfs_queue_map SEC(".maps");

PACKET_COUNT_MAP_DEFINE

static inline void __cuckoo_hash_enqueue_slot_back(struct cuckoo_hash *h,
						   uint32_t slot_id)
{
	struct simple_rbuf__cuckoo_hash_free_slots *free_slot_list;
	uint32_t *slot;

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
get_cuckoo_hash(struct cuckoo_hash_parameters *params)
{
	int zero = 0, i;
	struct cuckoo_hash *h;

	h = bpf_map_lookup_elem(&cuckoo_hash_map, &zero);
	if (h == NULL) {
		cuckoo_log(error, "cannot find cuckoo hash map");
		return NULL;
	}

	if (!h->initialized) {
		for (i = 1; i < CUCKOO_HASH_KEY_SLOTS; i++) {
			__cuckoo_hash_enqueue_slot_back(h, i);
		}
		h->initialized = 1;
	}

	return h;
}

static inline cuckoo_hash_sig_t __cuckoo_hash_hash(struct cuckoo_hash *h,
						   const cuckoo_hash_key_t *key)
{
	return crc32c(key, CUCKOO_HASH_KEY_SIZE, CUCKOO_HASH_SEED);
}

static inline uint16_t __cuckoo_hash_get_short_sig(const cuckoo_hash_sig_t hash)
{
	return hash >> 16;
}

static inline uint32_t
__cuckoo_hash_get_prim_bucket_index(struct cuckoo_hash *h,
				    const cuckoo_hash_sig_t hash)
{
	return hash & CUCKOO_HASH_BUCKET_BITMASK;
}

static inline uint32_t __cuckoo_hash_get_alt_bucket_index(struct cuckoo_hash *h,
							  uint32_t cur_bkt_idx,
							  uint16_t sig)
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
				struct __cuckoo_hash_bucket *bkt, uint16_t sig)
{
	uint32_t i;
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

static inline uint32_t __cuckoo_hash_alloc_slot(struct cuckoo_hash *h)
{
	struct simple_rbuf__cuckoo_hash_free_slots *free_slot_list;
	uint32_t *slot;

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
	uint16_t sig, uint32_t new_idx, int32_t *ret_val)
{
	unsigned int i;

	/* Insert new entry if there is room in the primary
	 * bucket.
	 */
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

	/* no empty entry */
	return -1;
}

static inline int __cuckoo_hash_cuckoo_move_insert_mw(
	struct cuckoo_hash *h, struct __cuckoo_hash_bucket *bkt,
	struct __cuckoo_hash_bucket *alt_bkt,
	const struct __cuckoo_hash_key *key, cuckoo_hash_value_t *data,
	struct __cuckoo_hash_bfs_queue *q, uint32_t leaf_node_idx,
	uint32_t leaf_slot, uint16_t sig, uint32_t new_idx, int32_t *ret_val)
{
	uint32_t prev_alt_bkt_idx;
	struct __cuckoo_hash_bfs_queue_node *prev_node,
		*curr_node = CUCKOO_HASH_GET_BFS_QUEUE_NODE(q, leaf_node_idx);
	struct __cuckoo_hash_bucket *prev_bkt,
		*curr_bkt = CUCKOO_HASH_GET_BUCKET(h, curr_node->bkt_idx);
	uint32_t prev_slot, curr_slot = leaf_slot;

	while (likely(curr_node->prev_node_idx != -1)) {
		prev_node = CUCKOO_HASH_GET_BFS_QUEUE_NODE(
			q, curr_node->prev_node_idx);
		prev_bkt = CUCKOO_HASH_GET_BUCKET(h, prev_node->bkt_idx);
		prev_slot = curr_node->prev_slot;

		prev_alt_bkt_idx = __cuckoo_hash_get_alt_bucket_index(
			h, prev_node->bkt_idx,
			prev_bkt->sig_current[prev_slot]);

		if (unlikely(&h->buckets[prev_alt_bkt_idx] != curr_bkt)) {
			/* revert it to empty, otherwise duplicated keys */
			curr_bkt->key_idx[curr_slot] = CUCKOO_HASH_EMPTY_SLOT;
			return -1;
		}

		/* Need to swap current/alt sig to allow later
		 * Cuckoo insert to move elements back to its
		 * primary bucket if available
		 */
		curr_bkt->sig_current[curr_slot] =
			prev_bkt->sig_current[prev_slot];
		curr_bkt->key_idx[curr_slot] = prev_bkt->key_idx[prev_slot];

		curr_slot = prev_slot;
		curr_node = prev_node;
		curr_bkt = CUCKOO_HASH_GET_BUCKET(h, curr_node->bkt_idx);
	}

	curr_bkt->sig_current[curr_slot] = sig;
	curr_bkt->key_idx[curr_slot] = new_idx;

	return 0;
}

static inline int __cuckoo_hash_cuckoo_make_space_mw(
	struct cuckoo_hash *h, uint32_t bkt_idx, uint32_t sec_bkt_idx,
	const struct __cuckoo_hash_key *key, cuckoo_hash_value_t *data,
	uint16_t sig, uint32_t new_idx, int32_t *ret_val)
{
	unsigned int i, zero = 0;
	struct __cuckoo_hash_bfs_queue *q;
	struct simple_rbuf__cuckoo_hash_bfs_queue *queue;
	struct __cuckoo_hash_bfs_queue_node *tail, *head;
	struct __cuckoo_hash_bucket *bkt, *sec_bkt, *curr_bkt, *alt_bkt;
	uint32_t cur_bkt_idx, alt_bkt_idx, *tail_node_idx, *head_node_idx;

	q = bpf_map_lookup_elem(&__cuckoo_hash_bfs_queue_map, &zero);
	if (q == NULL) {
		cuckoo_log(error, "cannot find bfs queue map");
		return -EINVAL;
	}

	queue = &q->bfs_queue;

	bkt = CUCKOO_HASH_GET_BUCKET(h, bkt_idx);
	sec_bkt = CUCKOO_HASH_GET_BUCKET(h, sec_bkt_idx);

	SIMPLE_RINGBUF_CLEAR(queue);
	tail = CUCKOO_HASH_GET_BFS_QUEUE_TAIL(q, tail_node_idx);
	tail->bkt_idx = bkt_idx;
	tail->prev_node_idx = -1;
	tail->prev_slot = -1;

	/* Cuckoo bfs Search */
	while (likely(!cuckoo_hash_bfs_queue__simple_rbuf_empty(queue) &&
		      !cuckoo_hash_bfs_queue__simple_rbuf_full(queue))) {
		tail = CUCKOO_HASH_GET_BFS_QUEUE_TAIL(q, tail_node_idx);
		cur_bkt_idx = tail->bkt_idx;
		curr_bkt = CUCKOO_HASH_GET_BUCKET(h, cur_bkt_idx);

		for (i = 0; i < CUCKOO_HASH_BUCKET_ENTRIES; i++) {
			if (curr_bkt->key_idx[i] == CUCKOO_HASH_EMPTY_SLOT) {
				int32_t ret =
					__cuckoo_hash_cuckoo_move_insert_mw(
						h, bkt, sec_bkt, key, data, q,
						*tail_node_idx, i, sig, new_idx,
						ret_val);
				if (likely(ret != -1))
					return ret;
			}

			/* Enqueue new node and keep prev node info */
			alt_bkt_idx = __cuckoo_hash_get_alt_bucket_index(
				h, cur_bkt_idx, curr_bkt->sig_current[i]);
			alt_bkt = CUCKOO_HASH_GET_BUCKET(h, alt_bkt_idx);

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
	struct cuckoo_hash *h, const cuckoo_hash_key_t *key,
	cuckoo_hash_sig_t sig, cuckoo_hash_value_t *data)
{
	uint16_t short_sig;
	uint32_t prim_bucket_idx, sec_bucket_idx;
	struct __cuckoo_hash_bucket *prim_bkt, *sec_bkt;
	struct __cuckoo_hash_key *new_k, *keys = h->key_store;
	uint32_t slot_id;
	int ret;
	int32_t ret_val;

	short_sig = __cuckoo_hash_get_short_sig(sig);
	prim_bucket_idx = __cuckoo_hash_get_prim_bucket_index(h, sig);
	sec_bucket_idx =
		__cuckoo_hash_get_alt_bucket_index(h, prim_bucket_idx, sig);
	prim_bkt = &h->buckets[prim_bucket_idx];
	sec_bkt = &h->buckets[sec_bucket_idx];

	/* Check if key is already inserted in primary location */
	ret = __cuckoo_hash_search_and_update(h, data, key, prim_bkt,
					      short_sig);
	if (ret != -1) {
		return ret;
	}

	/* Check if key is already inserted in secondary location */
	ret = __cuckoo_hash_search_and_update(h, data, key, sec_bkt, short_sig);
	if (ret != -1) {
		return ret;
	}

	slot_id = __cuckoo_hash_alloc_slot(h);
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

	/* Find an empty slot and insert */
	ret = __cuckoo_hash_cuckoo_insert_mw(h, prim_bkt, sec_bkt,
					     (struct __cuckoo_hash_key *)key,
					     data, short_sig, slot_id,
					     &ret_val);
	if (ret == 0) {
		return slot_id - 1;
	} else if (ret == 1) {
		__cuckoo_hash_enqueue_slot_back(h, slot_id);
		return ret_val;
	}

	/* Primary bucket full, need to make space for new entry */
	ret = __cuckoo_hash_cuckoo_make_space_mw(
		h, prim_bucket_idx, sec_bucket_idx,
		(struct __cuckoo_hash_key *)key, data, short_sig, slot_id,
		&ret_val);
	if (ret == 0) {
		return slot_id - 1;
	} else if (ret == 1) {
		__cuckoo_hash_enqueue_slot_back(h, slot_id);
		return ret_val;
	}

	/* Also search secondary bucket to get better occupancy */
	ret = __cuckoo_hash_cuckoo_make_space_mw(
		h, sec_bucket_idx, prim_bucket_idx,
		(struct __cuckoo_hash_key *)key, data, short_sig, slot_id,
		&ret_val);
	if (ret == 0) {
		return slot_id - 1;
	} else if (ret == 1) {
		__cuckoo_hash_enqueue_slot_back(h, slot_id);
		return ret_val;
	}

	/* ext table not enabled, we failed the insertion */
	__cuckoo_hash_enqueue_slot_back(h, slot_id);
	return ret;
}

static inline int cuckoo_hash_update_elem(struct cuckoo_hash *h,
					  cuckoo_hash_key_t *key,
					  cuckoo_hash_value_t *value)
{
	int ret;

	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);

	ret = __cuckoo_hash_add_key_with_hash(
		h, key, __cuckoo_hash_hash(h, key), value);
	if (ret >= 0) {
		return 0;
	} else {
		return ret;
	}
}

static int32_t __cuckoo_hash_search_one_bucket(struct cuckoo_hash *h,
					       const cuckoo_hash_key_t *key,
					       uint16_t sig,
					       cuckoo_hash_value_t **data,
					       struct __cuckoo_hash_bucket *bkt)
{
	uint32_t i;
	__cuckoo_hash_key_idx_t key_idx;
	struct __cuckoo_hash_key *k = NULL, *keys = h->key_store;

/* Added for benchmarks */
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
	/* We assume hash collisions are rare and compare keys only once */
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
		return 0; /* pretend the element is found to avoid secondary buckets being searched */
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
	uint32_t prim_bucket_idx, sec_bucket_idx;
	struct __cuckoo_hash_bucket *bkt, *cur_bkt;
	int ret, i;
	uint16_t short_sig;

	short_sig = __cuckoo_hash_get_short_sig(sig);
	prim_bucket_idx = __cuckoo_hash_get_prim_bucket_index(h, sig);
	sec_bucket_idx = __cuckoo_hash_get_alt_bucket_index(h, prim_bucket_idx,
							    short_sig);

	bkt = &h->buckets[prim_bucket_idx];

	/* Check if key is in primary location */
	ret = __cuckoo_hash_search_one_bucket(h, key, short_sig, data, bkt);
	if (ret != -1) {
		return ret;
	}

	bkt = &h->buckets[sec_bucket_idx];

	/* Check if key is in secondary location */
	ret = __cuckoo_hash_search_one_bucket(h, key, short_sig, data, bkt);
	if (ret != -1) {
		return ret;
	}

	return -ENOENT;
}

static inline int32_t cuckoo_hash_lookup_elem(struct cuckoo_hash *h,
					      const cuckoo_hash_key_t *key,
					      cuckoo_hash_value_t **data)
{
	int32_t ret;

	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);

	ret = __cuckoo_hash_lookup_with_hash(h, key, __cuckoo_hash_hash(h, key),
					     data);
	if (ret >= 0) {
		return 0;
	} else {
		return ret;
	}
}

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	LATENCY_START_TIMESTAMP_DEFINE

	struct cuckoo_hash_parameters params = {};
	struct cuckoo_hash *h;
	struct pkt_5tuple_with_pad pkt = { 0 };
	uint32_t *curr_count, count;
	void *data, *data_end;
	struct hdr_cursor nh;
	int ret;

	h = get_cuckoo_hash(&params);
	if (unlikely(h == NULL)) {
		cuckoo_log(error, "cannot get cuckoo hash");
		goto err;
	}

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	nh.pos = data;
	if (unlikely((ret = parse_pkt_5tuple(&nh, data_end, &pkt.pkt)) != 0)) {
		cuckoo_log(error, "cannot parse packet: %d", ret);
		goto err;
	} else {
		cuckoo_log(
			debug,
			"pkt: src_ip=0x%08x src_port=0x%04x dst_ip=0x%08x dst_port=0x%04x proto=0x%02x",
			pkt.pkt.src_ip, pkt.pkt.src_port, pkt.pkt.dst_ip,
			pkt.pkt.dst_port, pkt.pkt.proto);
	}

	ret = cuckoo_hash_lookup_elem(h, &pkt, &curr_count);
	if (likely(ret == 0)) {
		cuckoo_log(debug, "found packet: %d", *curr_count);
#ifdef CUCKOO_HASH_LOOKUP_ONLY
		cuckoo_log(debug, "lookup only");
		dummy = *curr_count;
#else
		*curr_count = *curr_count + 1;
		cuckoo_log(debug, "updated packet in place");
#endif
		goto out;
	} else {
		cuckoo_log(debug, "cannot find packet: %d", ret);
		count = 1;
	}

#ifdef CUCKOO_HASH_LOOKUP_ONLY
	cuckoo_log(debug, "lookup only");
#else
	ret = cuckoo_hash_update_elem(h, &pkt, &count);
	if (unlikely(ret != 0)) {
		cuckoo_log(error, "cannot update packet: %d", ret);
		goto err;
	} else {
		cuckoo_log(debug, "updated packet");
	}
#endif

out:
	PACKET_COUNT_MAP_UPDATE

#ifdef LATENCY_EXP
	SWAP_MAC_AND_RETURN_XDP_TX(ctx) 
#endif
err:
	return XDP_DROP;
}
