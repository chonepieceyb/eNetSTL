#ifndef __CUCKOO_HASH_OPERATIONS_H__
#define __CUCKOO_HASH_OPERATIONS_H__

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <linux/types.h>

/* Define unlikely macro for non-GCC compatibility */
#ifndef unlikely
#define unlikely(x) (x)
#endif

/* Define missing errno constants */
#ifndef ENOSPC
#define ENOSPC 28
#endif
#ifndef ENOENT
#define ENOENT 2
#endif

/* Type definitions for C compatibility */
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t s32;

/* Constants from eBPF version */

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
#define CUCKOO_HASH_ENTRIES 512
#endif

#define CUCKOO_HASH_KEY_SLOTS (CUCKOO_HASH_ENTRIES + 1)
#if !CUCKOO_IS_POWER_OF_2(CUCKOO_HASH_ENTRIES)
#error CUCKOO_HASH_ENTRIES must be a power of 2
#endif
#define CUCKOO_HASH_NUM_BUCKETS (CUCKOO_HASH_ENTRIES / CUCKOO_HASH_BUCKET_ENTRIES)
#define CUCKOO_HASH_BUCKET_BITMASK (CUCKOO_HASH_NUM_BUCKETS - 1)

#ifndef CUCKOO_HASH_KEY_SLOTS_SHIFT
#define CUCKOO_HASH_KEY_SLOTS_SHIFT 9
#endif
#if (1 << CUCKOO_HASH_KEY_SLOTS_SHIFT) != CUCKOO_HASH_ENTRIES
#error CUCKOO_HASH_KEY_SLOTS_SHIFT must be consistent with CUCKOO_HASH_ENTRIES
#endif

#ifndef CUCKOO_HASH_BFS_QUEUE_SHIFT
#define CUCKOO_HASH_BFS_QUEUE_SHIFT 10
#endif
#define CUCKOO_HASH_BFS_QUEUE_NODES (1 << (CUCKOO_HASH_BFS_QUEUE_SHIFT + 1))

/* Helper macros */
#define INDEX_WITH_BOUND(arr, idx, size)                                   \
    ({                                                                 \
        typeof((arr)) _arr = (arr);                                     \
        typeof((idx)) _idx = (idx);                                     \
        typeof((size)) _size = (size);                                   \
        if ((_idx) >= (_size)) {                                         \
            fprintf(stderr, "ERROR: idx %u >= size %u\n", (unsigned)(_idx), (unsigned)(_size)); \
            return (typeof(_arr))NULL;                                   \
        }                                                                 \
        (_arr) + (_idx);                                                 \
    })

#define SHIFT_TO_SIZE(shift) (1 << (shift))

/* Simple CRC32C implementation - compatible with eBPF version */
static inline u32 crc32c(u32 crc, const void *data, size_t length) {
    const u8 *bytes = (const u8 *)data;
    size_t i;

    crc = crc ^ 0xFFFFFFFF;

    for (i = 0; i < length; i++) {
        crc ^= bytes[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0x82F63B78 * (crc & 1));
        }
    }

    return crc ^ 0xFFFFFFFF;
}

/* Data types */
struct pkt_5tuple {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 proto;
} __attribute__((packed));

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
    fprintf(stderr, " cuckoo_hash: " fmt " (%s @ line %d)\n",     \
            ##__VA_ARGS__, __func__, __LINE__)

/* Forward declarations for simple ringbuf */
#define DECLARE_SIMPLE_RINGBUF(_name, _value_type, _size_shift)               \
    struct simple_rbuf__##_name {                                         \
        _value_type data[SHIFT_TO_SIZE((_size_shift))];               \
        u64 cons;                                                   \
        u64 prod;                                                   \
    };                                                                    \
    static __always_inline bool _name##__simple_rbuf_full(                \
        struct simple_rbuf__##_name *rb)                              \
    {                                                                     \
        return (rb)->prod - (rb)->cons == SHIFT_TO_SIZE(_size_shift); \
    }                                                                     \
    static __always_inline bool _name##__simple_rbuf_empty(               \
        struct simple_rbuf__##_name *rb)                              \
    {                                                                     \
        return (rb)->prod == (rb)->cons;                              \
    }                                                                     \
    static __always_inline _value_type *_name##__simple_rbuf_cons(        \
        struct simple_rbuf__##_name *rb)                              \
    {                                                                     \
        if (unlikely(_name##__simple_rbuf_empty((rb)))) {             \
            return NULL; /*ringbuf is empty*/                     \
        } else {                                                      \
            u64 _idx = (rb)->cons & (SHIFT_TO_SIZE(_size_shift) - 1); \
            return &((rb)->data[_idx]);                             \
        }                                                             \
    }                                                                     \
    static __always_inline void _name##__simple_rbuf_release(             \
        struct simple_rbuf__##_name *rb)                              \
    {                                                                     \
        ++((rb)->cons);                                               \
    }                                                                     \
    static __always_inline _value_type *_name##__simple_rbuf_prod(        \
        struct simple_rbuf__##_name *rb)                              \
    {                                                                     \
        if (unlikely(_name##__simple_rbuf_full((rb)))) {              \
            return NULL; /*ringbuf is full*/                      \
        } else {                                                      \
            u64 _idx = (rb)->prod & (SHIFT_TO_SIZE(_size_shift) - 1); \
            return &((rb)->data[_idx]);                             \
        }                                                             \
    }                                                                     \
    static __always_inline void _name##__simple_rbuf_submit(              \
        struct simple_rbuf__##_name *rb)                              \
    {                                                                     \
        ++((rb)->prod);                                               \
    }

DECLARE_SIMPLE_RINGBUF(cuckoo_hash_free_slots, u32, CUCKOO_HASH_KEY_SLOTS_SHIFT);
DECLARE_SIMPLE_RINGBUF(cuckoo_hash_bfs_queue, u32, CUCKOO_HASH_BFS_QUEUE_SHIFT);

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
    s32 prev_slot;
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
        cuckoo_log(stderr, "cannot enqueue slot %d", slot_id);
        return;
    }
    *slot = slot_id;
    cuckoo_hash_free_slots__simple_rbuf_submit(free_slot_list);
}

static inline struct cuckoo_hash *
get_cuckoo_hash(void *cuckoo_hash_map)
{
    s32 zero = 0, i;
    struct cuckoo_hash *h;

    if (cuckoo_hash_map == NULL) {
        cuckoo_log(stderr, "invalid cuckoo_hash_map parameter");
        return NULL;
    }

    h = *(struct cuckoo_hash **)cuckoo_hash_map;
    if (h == NULL) {
        cuckoo_log(stderr, "cannot find cuckoo hash map");
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
    return crc32c(CUCKOO_HASH_SEED, key, CUCKOO_HASH_KEY_SIZE);
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
    return memcmp(s1, s2, n);
}

static inline int __cuckoo_hash_cmp_eq(const cuckoo_hash_key_t *key1,
                       const cuckoo_hash_key_t *key2,
                       struct cuckoo_hash *h)
{
    return __cuckoo_hash_memcmp(key1, key2, sizeof(*key1));
}

static inline s32
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
                    stderr,
                    "invalid key index %d > CUCKOO_HASH_KEY_SLOTS %d",
                    key_idx, CUCKOO_HASH_KEY_SLOTS);
                return -EINVAL;
            }

            k = keys + key_idx;
            if (__cuckoo_hash_cmp_eq(key, &k->key, h) == 0) {
                memcpy(&k->value, data, CUCKOO_HASH_VALUE_SIZE);
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
        cuckoo_log(stderr, "cannot allocate slot");
        return CUCKOO_HASH_EMPTY_SLOT;
    }
    cuckoo_hash_free_slots__simple_rbuf_release(free_slot_list);

    return *slot;
}

static inline s32 __cuckoo_hash_cuckoo_insert_mw(
    struct cuckoo_hash *h, struct __cuckoo_hash_bucket *prim_bkt,
    struct __cuckoo_hash_bucket *sec_bkt,
    const struct __cuckoo_hash_key *key, cuckoo_hash_value_t *data,
    u16 sig, u32 new_idx, s32 *ret_val)
{
    unsigned int i;

    for (i = 0; i < CUCKOO_HASH_BUCKET_ENTRIES; i++) {
        if (prim_bkt->key_idx[i] == CUCKOO_HASH_EMPTY_SLOT) {
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
    u32 leaf_slot, u16 sig, u32 new_idx, s32 *ret_val)
{
    u32 prev_alt_bkt_idx;
    struct __cuckoo_hash_bfs_queue_node *prev_node,
        *curr_node = &q->bfs_queue_nodes[leaf_node_idx];
    struct __cuckoo_hash_bucket *prev_bkt,
        *curr_bkt = &params->hash_table->buckets[curr_node->bkt_idx];
    u32 prev_slot, curr_slot = leaf_slot;

    while (curr_node->prev_node_idx != (u32)-1) {
        prev_node = &q->bfs_queue_nodes[curr_node->prev_node_idx];
        prev_bkt = &params->hash_table->buckets[prev_node->bkt_idx];
        prev_slot = curr_node->prev_slot;

        prev_alt_bkt_idx = __cuckoo_hash_get_alt_bucket_index(
            params->hash_table, prev_node->bkt_idx,
            prev_bkt->sig_current[prev_slot]);

        if (&params->hash_table->buckets[prev_alt_bkt_idx] != curr_bkt) {
            curr_bkt->key_idx[curr_slot] = CUCKOO_HASH_EMPTY_SLOT;
            return -1;
        }

        curr_bkt->sig_current[curr_slot] =
            prev_bkt->sig_current[prev_slot];
        curr_bkt->key_idx[curr_slot] = prev_bkt->key_idx[prev_slot];

        curr_slot = prev_slot;
        curr_node = prev_node;
        curr_bkt = &params->hash_table->buckets[curr_node->bkt_idx];
    }

    curr_bkt->sig_current[curr_slot] = sig;
    curr_bkt->key_idx[curr_slot] = new_idx;

    return 0;
}

static inline int __cuckoo_hash_cuckoo_make_space_mw(
    struct cuckoo_hash_parameters *params, u32 bkt_idx, u32 sec_bkt_idx,
    const struct __cuckoo_hash_key *key, cuckoo_hash_value_t *data,
    u16 sig, u32 new_idx, s32 *ret_val)
{
    unsigned int i;
    struct __cuckoo_hash_bfs_queue *q;
    struct simple_rbuf__cuckoo_hash_bfs_queue *queue;
    struct __cuckoo_hash_bfs_queue_node *tail, *head;
    struct __cuckoo_hash_bucket *bkt, *sec_bkt, *curr_bkt, *alt_bkt;
    u32 cur_bkt_idx, alt_bkt_idx, *tail_node_idx, *head_node_idx;

    if (params == NULL || params->hash_table == NULL || params->bfs_queue == NULL) {
        cuckoo_log(stderr, "invalid parameters");
        return -EINVAL;
    }
    q = params->bfs_queue;

    queue = &q->bfs_queue;

    bkt = &params->hash_table->buckets[bkt_idx];
    sec_bkt = &params->hash_table->buckets[sec_bkt_idx];

    SIMPLE_RINGBUF_CLEAR(queue);
    tail = &q->bfs_queue_nodes[q->bfs_queue.prod & (CUCKOO_HASH_BFS_QUEUE_NODES - 1)];
    tail->bkt_idx = bkt_idx;
    tail->prev_node_idx = (u32)-1;
    tail->prev_slot = -1;
    q->bfs_queue.prod++;

    while (!cuckoo_hash_bfs_queue__simple_rbuf_empty(queue) &&
           !cuckoo_hash_bfs_queue__simple_rbuf_full(queue)) {
        tail = &q->bfs_queue_nodes[q->bfs_queue.cons & (CUCKOO_HASH_BFS_QUEUE_NODES - 1)];
        cur_bkt_idx = tail->bkt_idx;
        curr_bkt = &params->hash_table->buckets[cur_bkt_idx];

        for (i = 0; i < CUCKOO_HASH_BUCKET_ENTRIES; i++) {
            if (curr_bkt->key_idx[i] == CUCKOO_HASH_EMPTY_SLOT) {
                s32 ret =
                    __cuckoo_hash_cuckoo_move_insert_mw(
                        params, bkt, sec_bkt, key, data, q,
                        q->bfs_queue.cons - 1, i, sig, new_idx,
                        ret_val);
                if (ret != -1)
                    return ret;
            }

            alt_bkt_idx = __cuckoo_hash_get_alt_bucket_index(
                params->hash_table, cur_bkt_idx, curr_bkt->sig_current[i]);
            alt_bkt = &params->hash_table->buckets[alt_bkt_idx];

            head = &q->bfs_queue_nodes[q->bfs_queue.prod & (CUCKOO_HASH_BFS_QUEUE_NODES - 1)];
            head->bkt_idx = alt_bkt_idx;
            head->prev_node_idx = q->bfs_queue.cons - 1;
            head->prev_slot = i;
            q->bfs_queue.prod++;
        }
        q->bfs_queue.cons++;
    }

    return -ENOSPC;
}

static inline s32 __cuckoo_hash_add_key_with_hash(
    struct cuckoo_hash_parameters *params, const cuckoo_hash_key_t *key,
    cuckoo_hash_sig_t sig, cuckoo_hash_value_t *data)
{
    u16 short_sig;
    u32 prim_bucket_idx, sec_bucket_idx;
    struct __cuckoo_hash_bucket *prim_bkt, *sec_bkt;
    struct __cuckoo_hash_key *new_k, *keys = params->hash_table->key_store;
    u32 slot_id;
    int ret;
    s32 ret_val;

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
        cuckoo_log(stderr,
               "invalid key index %d > CUCKOO_HASH_KEY_SLOTS %d",
               slot_id, CUCKOO_HASH_KEY_SLOTS);
        return -EINVAL;
    }
    new_k = keys + slot_id;
    memcpy(&new_k->value, data, CUCKOO_HASH_VALUE_SIZE);
    memcpy(&new_k->key, key, CUCKOO_HASH_KEY_SIZE);

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

    if (((params == NULL) || (params->hash_table == NULL) || (key == NULL))) {
        return -EINVAL;
    }

    ret = __cuckoo_hash_add_key_with_hash(
        params, key, __cuckoo_hash_hash(params->hash_table, key), value);
    if (ret >= 0) {
        return 0;
    } else {
        return ret;
    }
}

static s32 __cuckoo_hash_search_one_bucket(struct cuckoo_hash *h,
                       const cuckoo_hash_key_t *key,
                       u16 sig,
                       cuckoo_hash_value_t **data,
                       struct __cuckoo_hash_bucket *bkt)
{
    u32 i;
    __cuckoo_hash_key_idx_t key_idx;
    struct __cuckoo_hash_key *k = NULL, *keys = h->key_store;

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
                    stderr,
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
        cuckoo_log(stderr, "found key at entry %d, key index %d", i,
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
                    stderr,
                    "invalid key index %d > CUCKOO_HASH_KEY_SLOTS %d",
                    bkt->key_idx[i], CUCKOO_HASH_KEY_SLOTS);
                return -EINVAL;
            }

            k = keys + key_idx;
            if (__cuckoo_hash_cmp_eq(key, &k->key, h) == 0) {
                *data = &k->value;
                cuckoo_log(
                    stderr,
                    "found key at entry %d, key index %d",
                    i, bkt->key_idx[i] - 1);
                return bkt->key_idx[i] - 1;
            }
        }
    }
#endif
    return -1;
}

static inline s32 __cuckoo_hash_lookup_with_hash(
    struct cuckoo_hash *h, const cuckoo_hash_key_t *key,
    cuckoo_hash_sig_t sig, cuckoo_hash_value_t **data)
{
    u32 prim_bucket_idx, sec_bucket_idx;
    struct __cuckoo_hash_bucket *bkt, *cur_bkt;
    s32 ret, i;
    u16 short_sig;

    short_sig = __cuckoo_hash_get_short_sig(sig);
    prim_bucket_idx = __cuckoo_hash_get_prim_bucket_index(h, sig);
    sec_bucket_idx = __cuckoo_hash_get_alt_bucket_index(h, prim_bucket_idx,
                        short_sig);

    bkt = &h->buckets[prim_bucket_idx];

    ret = __cuckoo_hash_search_one_bucket(h, key, short_sig, data, bkt);
    if (ret != -1) {
        return ret;
    }

    bkt = &h->buckets[sec_bucket_idx];

    ret = __cuckoo_hash_search_one_bucket(h, key, short_sig, data, bkt);
    if (ret != -1) {
        return ret;
    }

    return -ENOENT;
}

static inline s32 cuckoo_hash_lookup_elem(struct cuckoo_hash_parameters *params,
                     const cuckoo_hash_key_t *key,
                     cuckoo_hash_value_t **data)
{
    s32 ret;

    if (((params == NULL) || (params->hash_table == NULL) || (key == NULL))) {
        return -EINVAL;
    }

    ret = __cuckoo_hash_lookup_with_hash(params->hash_table, key, __cuckoo_hash_hash(params->hash_table, key),
                 data);
    if (ret >= 0) {
        return 0;
    } else {
        return ret;
    }
}

#endif /* __CUCKOO_HASH_OPERATIONS_H__ */