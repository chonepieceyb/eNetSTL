#include <asm-generic/errno-base.h>
#include <asm/fpu/api.h>
#include <asm/processor.h>
#include <linux/bpf.h>
#include <linux/cpumask.h>
#include <linux/err.h>
#include <linux/gfp_types.h>
#include <linux/list.h>
#include <linux/poison.h>
#include <linux/preempt.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/time32.h>
#include <linux/bitops.h>
#include <linux/bpf.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/xxhash.h>
#include <linux/percpu-defs.h>

#ifdef CUCKOO_HASH_DEBUG
#include "../test_helpers.h"
#include <linux/proc_fs.h>
#endif

#ifdef CUCKOO_HASH_SIMD
// This macro is required to include <immtrin.h> in the kernel
#define _MM_MALLOC_H_INCLUDED
#include <immintrin.h>
#endif

extern int bpf_register_static_cmap(struct bpf_map_ops *map,
				    struct module *owner);
extern void bpf_unregister_static_cmap(struct module *owner);
extern void bpf_map_area_free(void *area);
extern void *bpf_map_area_alloc(u64 size, int numa_node);

/** Type of function that can be used for calculating the hash value. */
static uint32_t __cuckoo_hash_hash_default(const void *key, uint32_t key_len,
					   uint32_t init_val)
{
	return xxh32(key, key_len, init_val);
}

#define cuckoo_log(level, fmt, ...) \
	pr_##level("cuckoo_hash: " fmt, ##__VA_ARGS__)

/** Type of function used to compare the hash key. */
typedef int (*__cuckoo_hash_cmp_eq_t)(const void *key1, const void *key2,
				      size_t key_len);

#define CUCKOO_IS_POWER_OF_2(n) ((n) && !(((n)-1) & (n)))

/**
 * Macro to align a value to a given power-of-two. The resultant value
 * will be of the same type as the first parameter, and will be no
 * bigger than the first parameter. Second parameter must be a
 * power-of-two value.
 */
#define CUCKOO_HASH_ALIGN_FLOOR(val, align) \
	(typeof(val))((val) & (~((typeof(val))((align)-1))))

/**
 * Macro to align a value to a given power-of-two. The resultant value
 * will be of the same type as the first parameter, and will be no lower
 * than the first parameter. Second parameter must be a power-of-two
 * value.
 */
#define CUCKOO_HASH_ALIGN_CEIL(val, align) \
	CUCKOO_HASH_ALIGN_FLOOR(((val) + ((typeof(val))(align)-1)), align)

/**
 * Macro to align a value to a given power-of-two. The resultant
 * value will be of the same type as the first parameter, and
 * will be no lower than the first parameter. Second parameter
 * must be a power-of-two value.
 * This function is the same as CUCKOO_HASH_ALIGN_CEIL
 */
#define CUCKOO_HASH_ALIGN(val, align) CUCKOO_HASH_ALIGN_CEIL(val, align)

#define CUCKOO_HASH_BUCKET_ENTRIES 8
#if !CUCKOO_IS_POWER_OF_2(CUCKOO_HASH_BUCKET_ENTRIES)
#error CUCKOO_HASH_BUCKET_ENTRIES must be a power of 2
#endif

#define CUCKOO_HASH_ENTRIES 128
#if !CUCKOO_IS_POWER_OF_2(CUCKOO_HASH_ENTRIES)
#error CUCKOO_HASH_ENTRIES must be a power of 2
#endif

#define CUCKOO_HASH_KEY_ALIGNMENT 16

#define CUCKOO_HASH_BFS_QUEUE_MAX_LEN 1000

#define CUCKOO_HASH_KEY_SIZE 16

#define CUCKOO_HASH_VALUE_SIZE 4

#define CUCKOO_HASH_SEED 0xdeadbeef

#define CUCKOO_HASH_KEY_SLOTS (CUCKOO_HASH_ENTRIES + 1)

#define CUCKOO_HASH_NUM_BUCKETS \
	(CUCKOO_HASH_ENTRIES / CUCKOO_HASH_BUCKET_ENTRIES)

#define CUCKOO_HASH_BUCKET_BITMASK (CUCKOO_HASH_NUM_BUCKETS - 1)

/* Structure that stores key-value pair */
struct __cuckoo_hash_key {
	/* Constant value size */
	char value[CUCKOO_HASH_VALUE_SIZE];
	/* Constant key size */
	char key[CUCKOO_HASH_KEY_SIZE];
};

#define CUCKOO_HASH_KEY_ENTRY_SIZE                          \
	CUCKOO_HASH_ALIGN(sizeof(struct __cuckoo_hash_key), \
			  CUCKOO_HASH_KEY_ALIGNMENT)

#define CUCKOO_HASH_EMPTY_SLOT 0

/**
 * add a byte-value offset to a pointer
 */
#define CUCKOO_HASH_PTR_ADD(ptr, x) ((void *)((uintptr_t)(ptr) + (x)))

/** Bucket structure */
struct __cuckoo_hash_bucket {
	uint16_t sig_current[CUCKOO_HASH_BUCKET_ENTRIES];
	uint32_t key_idx[CUCKOO_HASH_BUCKET_ENTRIES];
};

struct __cuckoo_hash_free_slot {
	struct list_head list;
	uint32_t slot_id;
};

/**
 * Parameters used when creating the hash table.
 */
struct cuckoo_hash_parameters {
	// All customization options are removed
};

/** A hash table structure. */
struct cuckoo_hash {
	struct __cuckoo_hash_free_slot free_slot_store[CUCKOO_HASH_KEY_SLOTS];
	struct list_head free_slot_list;
	/**< Ring that stores all indexes of the free slots in the key table */

	/* Fields used in lookup */

	void *key_store; /**< Table storing all keys and data */
	struct __cuckoo_hash_bucket buckets[CUCKOO_HASH_NUM_BUCKETS];
	/**< Table with buckets storing all the	hash values and key indexes
	 * to the key table.
	 */
};

struct cuckoo_hash_bpf_map {
	struct bpf_map map;
	struct cuckoo_hash __percpu *cuckoo_hash;
};

/* Macro to enable/disable run-time checking of function parameters */
#if defined(CUCKOO_HASH_DEBUG)
#define RETURN_IF_TRUE(cond, retval)   \
	do {                           \
		if (cond)              \
			return retval; \
	} while (0)
#else
#define RETURN_IF_TRUE(cond, retval)
#endif

/**
 * The type of hash value of a key.
 * It should be a value of at least 32bit with fully random pattern.
 */
typedef uint32_t cuckoo_hash_sig_t;

#ifdef CUCKOO_HASH_SIMD
/* Functions to compare multiple of 16 byte keys (up to 128 bytes) */
static inline int __cuckoo_hash_k16_cmp_eq(const void *key1, const void *key2,
					   size_t key_len)
{
	kernel_fpu_begin();

	const __m128i k1 = _mm_loadu_si128((const __m128i *)key1);
	const __m128i k2 = _mm_loadu_si128((const __m128i *)key2);
	const __m128i x = _mm_xor_si128(k1, k2);
	int ret = !_mm_test_all_zeros(x, x);

	kernel_fpu_end();

	return ret;
}

#define _mm256_loadu_si256_optional(ptr)                                       \
	(u64)(ptr) & ((1 << 5) - 1) ? _mm256_loadu_si256((__m256i_u *)(ptr)) : \
				      (*(__m256i *)(ptr))

#define _mm_loadu_si128_optional(ptr)                                       \
	(u64)(ptr) & ((1 << 5) - 1) ? _mm_loadu_si128((__m128i_u *)(ptr)) : \
				      *(__m128i *)(ptr)

static inline u32 __find_mask_u32_avx2(const u32 *arr, u32 val)
{
	__m256i arr_vec = _mm256_loadu_si256_optional(arr),
		val_vec = _mm256_set1_epi32(val);
	__m256i cmp = _mm256_cmpeq_epi32(arr_vec, val_vec);
	u32 mask = _mm256_movemask_epi8(cmp);
	return mask;
}

static inline u16 __find_mask_u16_sse2(const u16 *arr, u16 val)
{
	__m128i arr_vec = _mm_loadu_si128_optional((__m128i_u *)arr),
		val_vec = _mm_set1_epi16(val);
	__m128i cmp = _mm_cmpeq_epi16(arr_vec, val_vec);
	u16 mask = _mm_movemask_epi8(cmp);
	return mask;
}

static inline u32 find_u32_avx2(const u32 *arr, u32 val)
{
	u32 mask = __find_mask_u32_avx2(arr, val);
	return __tzcnt_u32(mask) >> 2;
}

static inline u32 find_u16_sse2(const u16 *arr, u16 val)
{
	u16 mask = __find_mask_u16_sse2(arr, val);
	return __tzcnt_u16(mask) >> 1;
}

static inline u32 find_mask_u32_avx2(const u32 *arr, u32 val)
{
	u32 _mask = __find_mask_u32_avx2(arr, val), mask = 0;
	int i;

	for (i = 0; i < 8; i++) {
		mask |= ((_mask >> (i << 2)) & 0x1) << i;
	}

	return mask;
}

static inline u32 find_mask_u16_sse2(const u16 *arr, u16 val)
{
	u16 _mask = __find_mask_u16_sse2(arr, val), mask = 0;
	int i;

	for (i = 0; i < 8; i++) {
		mask |= ((_mask >> (i << 1)) & 0x1) << i;
	}

	return mask;
}

#define for_each_bit_set(idx, mask, delta)                      \
	(delta) = __tzcnt_u32(mask);                            \
	for ((idx) = (delta); (mask); (mask) >>= ((delta) + 1), \
	    (delta) = __tzcnt_u32(mask), (idx) += (delta))

#define for_each_u32_avx2(arr, val, idx, mask, delta) \
	(mask) = find_mask_u32_avx2((arr), (val));    \
	for_each_bit_set((idx), (mask), (delta))

#define for_each_u16_sse2(arr, val, idx, mask, delta) \
	(mask) = find_mask_u16_sse2((arr), (val));    \
	for_each_bit_set((idx), (mask), (delta))
#endif

static inline int __cuckoo_hash_cmp_eq(const void *key1, const void *key2,
				       struct cuckoo_hash *h)
{
#ifdef CUCKOO_HASH_SIMD
#if CUCKOO_HASH_KEY_SIZE != 16
#error "__cuckoo_hash_k16_cmp_eq is used, but CUCKOO_HASH_KEY_SIZE is not 16"
#endif
	return __cuckoo_hash_k16_cmp_eq(key1, key2, CUCKOO_HASH_KEY_SIZE);
#else
	return memcmp(key1, key2, CUCKOO_HASH_KEY_SIZE);
#endif
}

static int
__cuckoo_hash_validate_parameters(struct cuckoo_hash_parameters *params)
{
	int ret = 0;

	if (params == NULL) {
		cuckoo_log(err, "%s: has no parameters\n", __func__);
		ret = -EINVAL;
		goto out;
	}

out:
	return ret;
}

static inline void
__cuckoo_hash_fill_parameters(struct cuckoo_hash_parameters *params,
			      union bpf_attr *attr)
{
	// Nothing to do
}

static int cuckoo_hash_alloc_check(union bpf_attr *attr)
{
	struct cuckoo_hash_parameters params;
	int ret;

	// Check basic attributes
	if (attr->key_size != CUCKOO_HASH_KEY_SIZE) {
		cuckoo_log(err, "key_size (%d) != CUCKOO_HASH_KEY_SIZE (%d)\n",
			   attr->key_size, CUCKOO_HASH_KEY_SIZE);
		ret = -EINVAL;
		goto out;
	}

	if (attr->value_size != CUCKOO_HASH_VALUE_SIZE) {
		cuckoo_log(err,
			   "value_size (%d) != CUCKOO_HASH_VALUE_SIZE (%d)\n",
			   attr->value_size, CUCKOO_HASH_VALUE_SIZE);
		ret = -EINVAL;
		goto out;
	}

	if (attr->max_entries != CUCKOO_HASH_ENTRIES) {
		cuckoo_log(err,
			   "max_entries (%d) != CUCKOO_HASH_ENTRIES (%d)\n",
			   attr->max_entries, CUCKOO_HASH_ENTRIES);
		ret = -EINVAL;
		goto out;
	}

	// Check cuckoo hash parameters
	__cuckoo_hash_fill_parameters(&params, attr);
	if ((ret = __cuckoo_hash_validate_parameters(&params)) != 0) {
		goto out;
	}

out:
	return ret;
}

int __cuckoo_hash_create_fields(struct cuckoo_hash *h,
				struct cuckoo_hash_parameters *params)
{
	struct __cuckoo_hash_free_slot *slot = NULL;
	void *keys = NULL;
	uint32_t i;
	int ret;

	if ((ret = __cuckoo_hash_validate_parameters(params)) != 0) {
		goto out;
	}

	const uint64_t key_tbl_size =
		CUCKOO_HASH_KEY_ENTRY_SIZE * CUCKOO_HASH_KEY_SLOTS;

	keys = kvzalloc(key_tbl_size, GFP_USER | __GFP_NOWARN);
	if (keys == NULL) {
		cuckoo_log(err, "key table memory allocation failed\n");
		ret = -ENOMEM;
		goto out;
	}

	/* Setup hash context */
	h->key_store = keys;

	INIT_LIST_HEAD(&h->free_slot_list);
	h->free_slot_store[0].list.next = LIST_POISON1;
	h->free_slot_store[0].list.prev = LIST_POISON2;
	/* Populate free slots list (queue). Entry zero is reserved for key misses. */
	for (i = 1; i < CUCKOO_HASH_KEY_SLOTS; i++) {
		slot = h->free_slot_store + i;
		slot->slot_id = i;
		// cuckoo_log(debug, "adding slot %d at %x\n", slot->slot_id, slot);
		list_add_tail(&slot->list, &h->free_slot_list);
	}

	goto out;

out_free_keys:
	kvfree(keys);
	keys = NULL;
out:
	return ret;
}

void __cuckoo_hash_free_fields(struct cuckoo_hash *h)
{
	if (h == NULL)
		return;

	if (h->key_store != NULL) {
		kvfree(h->key_store);
	}
}

static struct bpf_map *cuckoo_hash_alloc(union bpf_attr *attr)
{
	struct cuckoo_hash_bpf_map *cuckoo_hash_map;
	struct cuckoo_hash *cuckoo_hash;
	struct bpf_map *res;
	struct cuckoo_hash_parameters params;
	int ret, cpu;

	__cuckoo_hash_fill_parameters(&params, attr);

	cuckoo_hash = alloc_percpu_gfp(struct cuckoo_hash,
				       GFP_USER | __GFP_NOWARN | __GFP_ZERO);
	if (cuckoo_hash == NULL) {
		res = ERR_PTR(-ENOMEM);
		goto out;
	}

	for_each_possible_cpu(cpu) {
		ret = __cuckoo_hash_create_fields(per_cpu_ptr(cuckoo_hash, cpu),
						  &params);
		if (ret != 0) {
			res = ERR_PTR(ret);
			goto out_free_fields;
		}
	}

	cuckoo_hash_map = kvzalloc(sizeof(struct cuckoo_hash_bpf_map),
				   GFP_USER | __GFP_NOWARN);
	if (cuckoo_hash_map == NULL) {
		res = ERR_PTR(-ENOMEM);
		goto out_free_fields;
	}
	cuckoo_hash_map->cuckoo_hash = cuckoo_hash;
	res = (struct bpf_map *)cuckoo_hash_map;
	goto out;

out_free_fields:
	for_each_possible_cpu(cpu) {
		__cuckoo_hash_free_fields(per_cpu_ptr(cuckoo_hash, cpu));
	}
out_free_hash:
	free_percpu(cuckoo_hash);
out:
	return res;
}

static void cuckoo_hash_free(struct bpf_map *map)
{
	struct cuckoo_hash_bpf_map *cuckoo_hash_map;
	struct cuckoo_hash *cuckoo_hash;
	int cpu;

	if (map == NULL) {
		return;
	}

	cuckoo_hash_map = (struct cuckoo_hash_bpf_map *)map;
	cuckoo_hash = cuckoo_hash_map->cuckoo_hash;

	if (cuckoo_hash) {
		for_each_possible_cpu(cpu) {
			__cuckoo_hash_free_fields(
				per_cpu_ptr(cuckoo_hash, cpu));
		}
		free_percpu(cuckoo_hash);
	}

	kvfree(cuckoo_hash_map);
}

/*
 * We use higher 16 bits of hash as the signature value stored in table.
 * We use the lower bits for the primary bucket
 * location. Then we XOR primary bucket location and the signature
 * to get the secondary bucket location. This is same as
 * proposed in Bin Fan, et al's paper
 * "MemC3: Compact and Concurrent MemCache with Dumber Caching and
 * Smarter Hashing". The benefit to use
 * XOR is that one could derive the alternative bucket location
 * by only using the current bucket location and the signature.
 */
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

/* Search one bucket to find the match key - uses rw lock */
static inline int32_t
__cuckoo_hash_search_one_bucket(struct cuckoo_hash *h, const void *key,
				uint16_t sig, void **data,
				const struct __cuckoo_hash_bucket *bkt)
{
	int i;
	struct __cuckoo_hash_key *k, *keys = h->key_store;

#ifdef CUCKOO_HASH_SIMD
#if CUCKOO_HASH_BUCKET_ENTRIES != 8
#error "currently SIMD implementation requires CUCKOO_HASH_BUCKET_ENTRIES == 8"
#endif
	uint32_t mask, delta;
	mask = find_mask_u16_sse2(bkt->sig_current, sig) &
	       ~find_mask_u32_avx2(bkt->key_idx, CUCKOO_HASH_EMPTY_SLOT);
	cuckoo_log(debug, "mask = 0x%08x\n", mask);
	for_each_bit_set(i, mask, delta)
	{
#else
	for (i = 0; i < CUCKOO_HASH_BUCKET_ENTRIES; i++) {
		if (bkt->sig_current[i] == sig &&
		    bkt->key_idx[i] != CUCKOO_HASH_EMPTY_SLOT) {
#endif
		k = (struct __cuckoo_hash_key
			     *)((char *)keys +
				bkt->key_idx[i] * CUCKOO_HASH_KEY_ENTRY_SIZE);
		cuckoo_log(debug, "checking key i = %d, key_idx = %d\n", i,
			   bkt->key_idx[i]);

		if (__cuckoo_hash_cmp_eq(key, k->key, h) == 0) {
			cuckoo_log(debug, "key matches\n");

			if (data != NULL)
				*data = &k->value;
			/*
				 * Return index where key is stored,
				 * subtracting the first dummy index
				 */
			return bkt->key_idx[i] - 1;
		} else {
			cuckoo_log(debug, "key does not match\n");
		}
#ifndef CUCKOO_HASH_SIMD
	}
#endif
	}
	return -1;
}

static inline int32_t __cuckoo_hash_lookup_with_hash(struct cuckoo_hash *h,
						     const void *key,
						     cuckoo_hash_sig_t sig,
						     void **data)
{
	uint32_t prim_bucket_idx, sec_bucket_idx;
	struct __cuckoo_hash_bucket *bkt;
	int ret;
	uint16_t short_sig;

	cuckoo_log(debug, "looking up table\n");

	short_sig = __cuckoo_hash_get_short_sig(sig);
	cuckoo_log(debug, "short sig = %x", short_sig);
	prim_bucket_idx = __cuckoo_hash_get_prim_bucket_index(h, sig);
	cuckoo_log(debug, "prim_bucket_idx = %u", prim_bucket_idx);
	sec_bucket_idx = __cuckoo_hash_get_alt_bucket_index(h, prim_bucket_idx,
							    short_sig);
	cuckoo_log(debug, "sec_bucket_idx = %u", sec_bucket_idx);

	bkt = &h->buckets[prim_bucket_idx];

	/* Check if key is in primary location */
	ret = __cuckoo_hash_search_one_bucket(h, key, short_sig, data, bkt);
	cuckoo_log(debug, "search prim bucket: %d\n", ret);
	if (ret >= 0) {
		return 0;
	} else if (ret != -1) {
		return ret;
	}

	/* Calculate secondary hash */
	bkt = &h->buckets[sec_bucket_idx];

	/* Check if key is in secondary location */
	ret = __cuckoo_hash_search_one_bucket(h, key, short_sig, data, bkt);
	cuckoo_log(debug, "search sec bucket: %d\n", ret);
	if (ret >= 0) {
		return 0;
	}
	if (ret != -1) {
		return ret;
	}

	return -ENOENT;
}

cuckoo_hash_sig_t __cuckoo_hash_hash(struct cuckoo_hash *h, const void *key)
{
	/* calc hash result by key */
	return __cuckoo_hash_hash_default(key, CUCKOO_HASH_KEY_SIZE,
					  CUCKOO_HASH_SEED);
}

int __cuckoo_hash_lookup_data(struct cuckoo_hash *h, const void *key,
			      void **data)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
	return __cuckoo_hash_lookup_with_hash(h, key,
					      __cuckoo_hash_hash(h, key), data);
}

static void *cuckoo_hash_lookup_elem(struct bpf_map *map, void *key)
{
	struct cuckoo_hash_bpf_map *cuckoo_hash_map =
		(struct cuckoo_hash_bpf_map *)map;
	struct cuckoo_hash *cuckoo_hash;

	cuckoo_hash = this_cpu_ptr(cuckoo_hash_map->cuckoo_hash);

	void *data = NULL;
	int ret;
	ret = __cuckoo_hash_lookup_data(cuckoo_hash, key, &data);
	if (ret != 0) {
		cuckoo_log(debug, "lookup failed with code %d\n", ret);
		return NULL;
	} else {
		return data;
	}
}

/* Search a key from bucket and update its data.
 * Writer holds the lock before calling this.
 */
static inline int32_t
__cuckoo_hash_search_and_update(struct cuckoo_hash *h, void *data,
				const void *key,
				struct __cuckoo_hash_bucket *bkt, uint16_t sig)
{
	int i;
	struct __cuckoo_hash_key *k, *keys = h->key_store;

#ifdef CUCKOO_HASH_SIMD
#if CUCKOO_HASH_BUCKET_ENTRIES != 8
#error "currently SIMD implementation requires CUCKOO_HASH_BUCKET_ENTRIES == 8"
#endif
	uint32_t mask, delta;
	for_each_u16_sse2(bkt->sig_current, sig, i, mask, delta)
	{
#else
	for (i = 0; i < CUCKOO_HASH_BUCKET_ENTRIES; i++) {
		if (bkt->sig_current[i] == sig) {
#endif
		k = (struct __cuckoo_hash_key
			     *)((char *)keys +
				bkt->key_idx[i] * CUCKOO_HASH_KEY_ENTRY_SIZE);
		if (__cuckoo_hash_cmp_eq(key, k->key, h) == 0) {
			memcpy(&k->value, data, CUCKOO_HASH_VALUE_SIZE);
			/*
				 * Return index where key is stored,
				 * subtracting the first dummy index
				 */
			return bkt->key_idx[i] - 1;
#ifndef CUCKOO_HASH_SIMD
		}
#endif
	}
	}
	return -1;
}

static inline uint32_t __cuckoo_hash_alloc_slot(struct cuckoo_hash *h)
{
	uint32_t slot_id;
	struct __cuckoo_hash_free_slot *free_slot;

	if (list_empty(&h->free_slot_list)) {
		slot_id = CUCKOO_HASH_EMPTY_SLOT;
	} else {
		free_slot = list_first_entry(&h->free_slot_list,
					     struct __cuckoo_hash_free_slot,
					     list);
		list_del(&free_slot->list);
		slot_id = free_slot->slot_id;
	}

	return slot_id;
}

static inline int __cuckoo_hash_enqueue_slot_back(struct cuckoo_hash *h,
						  uint32_t slot_id)
{
	struct __cuckoo_hash_free_slot *slot = h->free_slot_store + slot_id;

	// We use poison values to ensure that slot is not used; see list_del()
	if (slot->list.next != LIST_POISON1 ||
	    slot->list.prev != LIST_POISON2) {
		cuckoo_log(debug, "slot_id %u is already in the free list\n",
			   slot_id);
		return -EEXIST;
	}

	// list_add_tail(&h->free_slot_list, &slot->list);
	list_add_tail(&slot->list, &h->free_slot_list);
	return 0;
}

/* Only tries to insert at one bucket (@prim_bkt) without trying to push
 * buckets around.
 * return 1 if matching existing key, return 0 if succeeds, return -1 for no
 * empty entry.
 */
static inline int32_t
__cuckoo_hash_cuckoo_insert_mw(struct cuckoo_hash *h,
			       struct __cuckoo_hash_bucket *prim_bkt,
			       struct __cuckoo_hash_bucket *sec_bkt,
			       const struct __cuckoo_hash_key *key, void *data,
			       uint16_t sig, uint32_t new_idx, int32_t *ret_val)
{
	unsigned int i;

	/* Insert new entry if there is room in the primary
	 * bucket.
	 */
#ifdef CUCKOO_HASH_SIMD
#if CUCKOO_HASH_BUCKET_ENTRIES != 8
#error "currently SIMD implementation requires CUCKOO_HASH_BUCKET_ENTRIES == 8"
#endif
	i = find_u32_avx2(prim_bkt->key_idx, CUCKOO_HASH_EMPTY_SLOT);

	if (i == 8) {
		/* no empty entry */
		return -1;
	}

	prim_bkt->sig_current[i] = sig;
	prim_bkt->key_idx[i] = new_idx;
	return 0;
#else
	for (i = 0; i < CUCKOO_HASH_BUCKET_ENTRIES; i++) {
		/* Check if slot is available */
		if (likely(prim_bkt->key_idx[i] == CUCKOO_HASH_EMPTY_SLOT)) {
			prim_bkt->sig_current[i] = sig;
			/* Store to signature and key should not
			 * leak after the store to key_idx. i.e.
			 * key_idx is the guard variable for signature
			 * and key.
			 */
			prim_bkt->key_idx[i] = new_idx;
			break;
		}
	}

	if (i != CUCKOO_HASH_BUCKET_ENTRIES)
		return 0;

	/* no empty entry */
	return -1;
#endif
}

struct __cuckoo_hash_bfs_queue_node {
	struct __cuckoo_hash_bucket *bkt; /* Current bucket on the bfs search */
	uint32_t cur_bkt_idx;

	struct __cuckoo_hash_bfs_queue_node
		*prev; /* Parent(bucket) in search path */
	int prev_slot; /* Parent(slot) in search path */
};

/* Shift buckets along provided cuckoo_path (@leaf and @leaf_slot) and fill
 * the path head with new entry (sig, alt_hash, new_idx)
 * return 1 if matched key found, return -1 if cuckoo path invalided and fail,
 * return 0 if succeeds.
 */
static inline int __cuckoo_hash_cuckoo_move_insert_mw(
	struct cuckoo_hash *h, struct __cuckoo_hash_bucket *bkt,
	struct __cuckoo_hash_bucket *alt_bkt,
	const struct __cuckoo_hash_key *key, void *data,
	struct __cuckoo_hash_bfs_queue_node *leaf, uint32_t leaf_slot,
	uint16_t sig, uint32_t new_idx, int32_t *ret_val)
{
	uint32_t prev_alt_bkt_idx;
	struct __cuckoo_hash_bfs_queue_node *prev_node, *curr_node = leaf;
	struct __cuckoo_hash_bucket *prev_bkt, *curr_bkt = leaf->bkt;
	uint32_t prev_slot, curr_slot = leaf_slot;

	while (likely(curr_node->prev != NULL)) {
		prev_node = curr_node->prev;
		prev_bkt = prev_node->bkt;
		prev_slot = curr_node->prev_slot;

		prev_alt_bkt_idx = __cuckoo_hash_get_alt_bucket_index(
			h, prev_node->cur_bkt_idx,
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
		curr_bkt = curr_node->bkt;
	}

	curr_bkt->sig_current[curr_slot] = sig;
	curr_bkt->key_idx[curr_slot] = new_idx;

	return 0;
}

/*
 * Make space for new key, using bfs Cuckoo Search and Multi-Writer safe
 * Cuckoo
 */
static inline int __cuckoo_hash_cuckoo_make_space_mw(
	struct cuckoo_hash *h, struct __cuckoo_hash_bucket *bkt,
	struct __cuckoo_hash_bucket *sec_bkt,
	const struct __cuckoo_hash_key *key, void *data, uint16_t sig,
	uint32_t bucket_idx, uint32_t new_idx, int32_t *ret_val)
{
	unsigned int i;
	struct __cuckoo_hash_bfs_queue_node *queue;
	struct __cuckoo_hash_bfs_queue_node *tail, *head;
	struct __cuckoo_hash_bucket *curr_bkt, *alt_bkt;
	uint32_t cur_idx, alt_idx;
	int32_t ret;
#ifdef CUCKOO_HASH_SIMD
	uint32_t mask, delta;
#endif

	queue = kvzalloc(sizeof(struct __cuckoo_hash_bfs_queue_node) *
				 CUCKOO_HASH_BFS_QUEUE_MAX_LEN,
			 GFP_KERNEL);
	if (queue == NULL) {
		cuckoo_log(err, "failed to allocate memory for BFS queue\n");
		ret = -ENOMEM;
		goto out;
	}

	tail = queue;
	head = queue + 1;
	tail->bkt = bkt;
	tail->prev = NULL;
	tail->prev_slot = -1;
	tail->cur_bkt_idx = bucket_idx;

	/* Cuckoo bfs Search */
	while (likely(tail != head &&
		      head < queue + CUCKOO_HASH_BFS_QUEUE_MAX_LEN -
				      CUCKOO_HASH_BUCKET_ENTRIES)) {
		curr_bkt = tail->bkt;
		cur_idx = tail->cur_bkt_idx;
		cuckoo_log(debug, "iterating: queue size = %ld, cur_idx = %d\n",
			   head - tail, cur_idx);
#ifdef CUCKOO_HASH_SIMD
#if CUCKOO_HASH_BUCKET_ENTRIES != 8
#error "currently SIMD implementation requires CUCKOO_HASH_BUCKET_ENTRIES == 8"
#endif
		for_each_u32_avx2(curr_bkt->key_idx, CUCKOO_HASH_EMPTY_SLOT, i,
				  mask, delta)
		{
			ret = __cuckoo_hash_cuckoo_move_insert_mw(
				h, bkt, sec_bkt, key, data, tail, i, sig,
				new_idx, ret_val);
			cuckoo_log(debug, "%d: done move insert ret = %d\n", i,
				   ret);
			if (likely(ret != -1))
				goto out_free_queue;
		}

		for (i = 0; i < CUCKOO_HASH_BUCKET_ENTRIES; i++) {
#else
		for (i = 0; i < CUCKOO_HASH_BUCKET_ENTRIES; i++) {
			if (curr_bkt->key_idx[i] == CUCKOO_HASH_EMPTY_SLOT) {
				ret = __cuckoo_hash_cuckoo_move_insert_mw(
					h, bkt, sec_bkt, key, data, tail, i,
					sig, new_idx, ret_val);
				cuckoo_log(debug,
					   "%d: done move insert ret = %d\n", i,
					   ret);
				if (likely(ret != -1))
					goto out_free_queue;
			} else {
				cuckoo_log(debug, "%d: skipped move insert\n",
					   i);
			}
#endif

			/* Enqueue new node and keep prev node info */
			alt_idx = __cuckoo_hash_get_alt_bucket_index(
				h, cur_idx, curr_bkt->sig_current[i]);
			cuckoo_log(debug, "got alt index = %d\n", alt_idx);
			alt_bkt = &(h->buckets[alt_idx]);
			cuckoo_log(debug, "got alt bkt = %llx\n",
				   (unsigned long long)alt_bkt);
			head->bkt = alt_bkt;
			head->cur_bkt_idx = alt_idx;
			head->prev = tail;
			head->prev_slot = i;
			head++;
			cuckoo_log(debug, "%d: done othera\n", i);
		}
		tail++;
	}

	return -ENOSPC;

out_free_queue:
	kvfree(queue);
out:
	return ret;
}

static inline int32_t __cuckoo_hash_add_key_with_hash(struct cuckoo_hash *h,
						      const void *key,
						      cuckoo_hash_sig_t sig,
						      void *data)
{
	uint16_t short_sig;
	uint32_t prim_bucket_idx, sec_bucket_idx;
	struct __cuckoo_hash_bucket *prim_bkt, *sec_bkt;
	struct __cuckoo_hash_key *new_k, *keys = h->key_store;
	uint32_t slot_id;
	int ret;
	int32_t ret_val;

	cuckoo_log(debug, "adding key with hash\n");

	short_sig = __cuckoo_hash_get_short_sig(sig);
	cuckoo_log(debug, "short sig = %x\n", short_sig);
	prim_bucket_idx = __cuckoo_hash_get_prim_bucket_index(h, sig);
	cuckoo_log(debug, "prim_bucket_idx = %u\n", prim_bucket_idx);
	sec_bucket_idx = __cuckoo_hash_get_alt_bucket_index(h, prim_bucket_idx,
							    short_sig);
	cuckoo_log(debug, "sec_bucket_idx = %u\n", sec_bucket_idx);
	prim_bkt = &h->buckets[prim_bucket_idx];
	sec_bkt = &h->buckets[sec_bucket_idx];

	/* Check if key is already inserted in primary location */
	ret = __cuckoo_hash_search_and_update(h, data, key, prim_bkt,
					      short_sig);
	if (ret != -1) {
		cuckoo_log(debug, "already in prim bucket\n");
		return ret;
	}

	/* Check if key is already inserted in secondary location */
	ret = __cuckoo_hash_search_and_update(h, data, key, sec_bkt, short_sig);
	if (ret != -1) {
		cuckoo_log(debug, "already in sec bucket\n");
		return ret;
	}

	/* Did not find a match, so get a new slot for storing the new key */
	slot_id = __cuckoo_hash_alloc_slot(h);
	if (slot_id == CUCKOO_HASH_EMPTY_SLOT) {
		cuckoo_log(debug, "no space 1\n");
		return -ENOSPC;
	}

	new_k = CUCKOO_HASH_PTR_ADD(keys, slot_id * CUCKOO_HASH_KEY_ENTRY_SIZE);
	memcpy(&new_k->value, data, CUCKOO_HASH_VALUE_SIZE);
	/* Copy key */
	memcpy(new_k->key, key, CUCKOO_HASH_KEY_SIZE);

	/* Find an empty slot and insert */
	ret = __cuckoo_hash_cuckoo_insert_mw(h, prim_bkt, sec_bkt, key, data,
					     short_sig, slot_id, &ret_val);
	cuckoo_log(debug, "prim bucket insert: %d, slot_id = %d\n", ret,
		   slot_id);
	if (ret == 0)
		return slot_id - 1;
	else if (ret == 1) {
		__cuckoo_hash_enqueue_slot_back(h, slot_id);
		return ret_val;
	}

	/* Primary bucket full, need to make space for new entry */
	cuckoo_log(debug, "start making space\n");
	ret = __cuckoo_hash_cuckoo_make_space_mw(h, prim_bkt, sec_bkt, key,
						 data, short_sig,
						 prim_bucket_idx, slot_id,
						 &ret_val);
	cuckoo_log(debug, "make space prim: %d\n", ret);
	if (ret == 0)
		return slot_id - 1;
	else if (ret == 1) {
		__cuckoo_hash_enqueue_slot_back(h, slot_id);
		return ret_val;
	}

	/* Also search secondary bucket to get better occupancy */
	ret = __cuckoo_hash_cuckoo_make_space_mw(h, sec_bkt, prim_bkt, key,
						 data, short_sig,
						 sec_bucket_idx, slot_id,
						 &ret_val);
	cuckoo_log(debug, "make space sec: %d\n", ret);

	if (ret == 0)
		return slot_id - 1;
	else if (ret == 1) {
		__cuckoo_hash_enqueue_slot_back(h, slot_id);
		return ret_val;
	}

	/* ext table is not enabled, so we failed the insertion */
	cuckoo_log(debug, "no space 2\n");
	__cuckoo_hash_enqueue_slot_back(h, slot_id);
	return ret;
}

int __cuckoo_hash_add_key_data(struct cuckoo_hash *h, const void *key,
			       void *data)
{
	int ret;

	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);

	ret = __cuckoo_hash_add_key_with_hash(h, key,
					      __cuckoo_hash_hash(h, key), data);
	if (ret >= 0)
		return 0;
	else
		return ret;
}

static long cuckoo_hash_update_elem(struct bpf_map *map, void *key, void *value,
				    u64 flags)
{
	struct cuckoo_hash_bpf_map *cuckoo_hash_map =
		(struct cuckoo_hash_bpf_map *)map;
	struct cuckoo_hash *cuckoo_hash;

	cuckoo_hash = this_cpu_ptr(cuckoo_hash_map->cuckoo_hash);

	return __cuckoo_hash_add_key_data(cuckoo_hash, key, value);
}

static u64 cuckoo_hash_mem_usage(const struct bpf_map *map)
{
	struct cuckoo_hash_bpf_map *cuckoo_hash_map =
		(struct cuckoo_hash_bpf_map *)map;
	struct cuckoo_hash *cuckoo_hash =
		per_cpu_ptr(cuckoo_hash_map->cuckoo_hash, 0);
	u64 size = 0;

	size += sizeof(*map);
	size += (sizeof(*cuckoo_hash) +
		 sizeof(cuckoo_hash->free_slot_store[0]) *
			 CUCKOO_HASH_KEY_SLOTS +
		 sizeof(cuckoo_hash->buckets[0]) * CUCKOO_HASH_NUM_BUCKETS +
		 CUCKOO_HASH_KEY_ENTRY_SIZE * CUCKOO_HASH_KEY_SLOTS) *
		num_possible_cpus();

	return size;
}

static struct bpf_map_ops cuckoo_hash_ops = {
	.map_alloc_check = cuckoo_hash_alloc_check,
	.map_alloc = cuckoo_hash_alloc,
	.map_free = cuckoo_hash_free,
	.map_lookup_elem = cuckoo_hash_lookup_elem,
	.map_update_elem = cuckoo_hash_update_elem,
	.map_mem_usage = cuckoo_hash_mem_usage,
};

static int cuckoo_hash_initialize(void)
{
	return 0;
}

#ifdef CUCKOO_HASH_DEBUG
static struct proc_dir_entry *ent;

struct pkt_5tuple {
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	uint8_t proto;
	/* make this structure 16 bytes to use __cuckoo_hash_k16_cmp_eq */
	uint8_t pad[3];
} __attribute__((packed));

static int __testing_alloc(struct inode *inode, struct file *filp)
{
	struct bpf_map *map;
	union bpf_attr attr;
	int ret = 0;

	cuckoo_log(debug, "try module get\n");
	if (!try_module_get(THIS_MODULE)) {
		ret = -ENODEV;
		cuckoo_log(err, "failed to take module\n");
		goto out;
	}

	/*testing alloc here*/
	cuckoo_log(debug, "start testing alloc\n");

	attr.key_size = sizeof(struct pkt_5tuple);
	attr.value_size = sizeof(uint32_t);
	attr.max_entries = 128;

	if ((ret = cuckoo_hash_alloc_check(&attr))) {
		cuckoo_log(err, "failed to check alloc: %d\n", ret);
		goto out;
	}

	map = cuckoo_hash_alloc(&attr);
	if (IS_ERR_OR_NULL(map)) {
		ret = PTR_ERR(map);
		cuckoo_log(err, "failed to alloc map: %d\n", ret);
		goto out;
	}
	cuckoo_log(debug, "testing alloc success\n");
	filp->private_data = (void *)map;

out:
	return ret;
}

static int __testing_release(struct inode *inode, struct file *file)
{
	struct bpf_map *map;

	cuckoo_log(debug, "start testing free\n");
	/*testing free here*/
	map = (struct bpf_map *)file->private_data;
	cuckoo_log(debug, "testing free\n");
	cuckoo_hash_free(map);
	cuckoo_log(debug, "testing free success\n");
	module_put(THIS_MODULE);
	return 0;
}

static ssize_t __testing_operation(struct file *flip, char __user *ubuf,
				   size_t count, loff_t *ppos)
{
	/* testing data structure operation*/
	struct bpf_map *map;
	int ret = 0;
	uint32_t *data;

	cuckoo_log(debug, "testing cuckoo hash operation\n");
	map = (struct bpf_map *)(flip->private_data);

	struct pkt_5tuple keys[32];
	uint32_t values[32];

	for (int i = 0; i < 4; ++i) {
		get_random_bytes(keys, sizeof(keys));
		get_random_bytes(values, sizeof(values));

		for (int j = 0; j < 32; ++j) {
			cuckoo_log(debug, "testing i = %d, j = %d\n", i, j);

			preempt_disable();
			ret = cuckoo_hash_update_elem(map, keys + j, values + j,
						      BPF_ANY);
			preempt_enable();
			lkm_assert_eq(0, ret,
				      "cuckoo_hash_update_elem should succeed");

			preempt_disable();
			data = cuckoo_hash_lookup_elem(map, keys + j);
			preempt_enable();
			lkm_assert_eq(0, IS_ERR_OR_NULL(data),
				      "cuckoo_hash_lookup_elem should succeed");
			lkm_assert_eq(
				values[j], *data,
				"cuckoo_hash_lookup_elem should return correct value");
		}
	}

	get_random_bytes(keys, sizeof(keys));
	get_random_bytes(values, sizeof(values));

	for (int i = 0; i < 32; ++i) {
		cuckoo_log(debug, "testing i = %d\n", i);

		preempt_disable();
		ret = cuckoo_hash_update_elem(map, keys + i, values + i,
					      BPF_ANY);
		preempt_enable();
		lkm_assert_eq(
			-ENOSPC, ret,
			"cuckoo_hash_update_elem should fail with ENOSPC");

		preempt_disable();
		data = cuckoo_hash_lookup_elem(map, keys + i);
		preempt_enable();
		lkm_assert_eq(NULL, data,
			      "cuckoo_hash_lookup_elem should return NULL");
	}

	cuckoo_log(info, "testing cuckoo_hash success\n");
	return 0; /*always not insert the mod*/

lkm_test_error:
	cuckoo_log(err, "testing cuckoo_hash failed with res %d\n", ret);
	return 0;
}

static struct proc_ops testing_ops = {
	.proc_open = __testing_alloc,
	.proc_read = __testing_operation,
	.proc_release = __testing_release,
};

static int cuckoo_hash_proc_init(void)
{
	ent = proc_create("testing_cuckoo", 0440, NULL, &testing_ops);
	if (IS_ERR_OR_NULL(ent))
		return -2;
	return 0;
}

static void cuckoo_hash_proc_cleanup(void)
{
	proc_remove(ent);
}
#endif

static int __init cuckoo_hash_init(void)
{
	int ret = 0;

	if ((ret = cuckoo_hash_initialize()) != 0) {
		cuckoo_log(err, "failed to initialize\n");
		goto out;
	}

	if ((ret = bpf_register_static_cmap(&cuckoo_hash_ops, THIS_MODULE)) !=
	    0) {
		cuckoo_log(err, "failed to register static cmap\n");
		goto out;
	}

#ifdef CUCKOO_HASH_DEBUG
	if ((ret = cuckoo_hash_proc_init()) != 0) {
		cuckoo_log(err, "failed to initialize proc\n");
		goto out;
	}
#endif

	cuckoo_log(info, "initialized\n");

out:
	return ret;
}

static void __exit cuckoo_hash_exit(void)
{
#ifdef CUCKOO_HASH_DEBUG
	cuckoo_hash_proc_cleanup();
#endif
	bpf_unregister_static_cmap(THIS_MODULE);

	cuckoo_log(info, "exiting\n");
}

/* Register module functions */
module_init(cuckoo_hash_init);
module_exit(cuckoo_hash_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yang Hanlin");
MODULE_DESCRIPTION("Cuckoo hash LKM implementation");
MODULE_VERSION("0.0.1");
