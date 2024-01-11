#include "linux/percpu-defs.h"
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
typedef uint32_t (*__cuckoo_hash_function)(const void *key, uint32_t key_len,
					   uint32_t init_val);

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

// FIXME:
#define __cuckoo_hash_cache_aligned

/**
 * Parameters used when creating the hash table.
 */
struct cuckoo_hash_parameters {
	uint32_t entries; /**< Total hash table entries. */
	uint32_t key_len; /**< Length of hash key. */
	uint32_t hash_func_init_val; /**< Init value used by hash_func. */
	uint8_t extra_flag; /**< Indicate if additional parameters are present. */
};

#ifdef CUCKOO_HASH_SIMD
/*
 * All different options to select a key compare function,
 * based on the key size and custom function.
 */
enum __cuckoo_hash_cmp_jump_table_case {
	KEY_16_BYTES = 1,
	KEY_OTHER_BYTES,
	NUM_KEY_CMP_CASES,
};
#else
/*
 * All different options to select a key compare function,
 * based on the key size and custom function.
 */
enum __cuckoo_hash_cmp_jump_table_case {
	KEY_OTHER_BYTES = 1,
	NUM_KEY_CMP_CASES,
};
#endif

/* All different signature compare functions */
enum __cuckoo_hash_sig_compare_function {
	CUCKOO_HASH_COMPARE_SCALAR = 0,
	CUCKOO_HASH_COMPARE_SSE,
	CUCKOO_HASH_COMPARE_NEON,
	CUCKOO_HASH_COMPARE_NUM
};

/**
 * Number of items per bucket.
 * 8 is a tradeoff between performance and memory consumption.
 * When it is equal to 8, multiple 'struct CUCKOO_HASH_hash_bucket' can be fit
 * on a single cache line (64 or 128 bytes long) without any gaps
 * in memory between them due to alignment.
 */
#define CUCKOO_HASH_BUCKET_ENTRIES 8

/** Bucket structure */
struct __cuckoo_hash_bucket {
	uint16_t sig_current[CUCKOO_HASH_BUCKET_ENTRIES];
	uint32_t key_idx[CUCKOO_HASH_BUCKET_ENTRIES];
} __cuckoo_hash_cache_aligned;

struct __cuckoo_hash_free_slot {
	struct list_head list;
	uint32_t slot_id;
};

/** A hash table structure. */
struct cuckoo_hash {
	uint32_t entries; /**< Total table entries. */
	uint32_t num_buckets; /**< Number of buckets in table. */

	struct __cuckoo_hash_free_slot *free_slot_store;
	struct list_head free_slot_list;
	/**< Ring that stores all indexes of the free slots in the key table */

	/* Fields used in lookup */

	uint32_t key_len __cuckoo_hash_cache_aligned;
	/**< Length of hash key. */
	__cuckoo_hash_function hash_func; /**< Function used to calculate hash. */
	uint32_t hash_func_init_val; /**< Init value used by hash_func. */
	enum __cuckoo_hash_cmp_jump_table_case cmp_jump_table_idx;
	/**< Indicates which compare function to use. */
	enum __cuckoo_hash_sig_compare_function sig_cmp_fn;
	/**< Indicates which signature compare function to use. */
	uint32_t bucket_bitmask;
	/**< Bitmask for getting bucket index from hash signature. */
	uint32_t key_entry_size; /**< Size of each key entry. */

	void *key_store; /**< Table storing all keys and data */
	struct __cuckoo_hash_bucket *buckets;
	/**< Table with buckets storing all the	hash values and key indexes
	 * to the key table.
	 */
} __cuckoo_hash_cache_aligned;

/** Maximum size of hash table that can be created. */
#define CUCKOO_HASH_ENTRIES_MAX (1 << 30)

#define CUCKOO_HASH_KEY_ALIGNMENT 16

/* Mask of all flags supported by this version (no flag is currently supported) */
#define CUCKOO_HASH_EXTRA_FLAGS_MASK 0x0

#define CUCKOO_HASH_BFS_QUEUE_MAX_LEN 1000

#define CUCKOO_HASH_VALUE_SIZE 4

#define CUCKOO_HASH_SEED 0xdeadbeef

/**
 * Combines 32b inputs most significant set bits into the least
 * significant bits to construct a value with the same MSBs as x
 * but all 1's under it.
 *
 * @param x
 *    The integer whose MSBs need to be combined with its LSBs
 * @return
 *    The combined value.
 */
static inline uint32_t __cuckoo_hash_combine32ms1b(uint32_t x)
{
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;

	return x;
}

/**
 * Aligns input parameter to the next power of 2
 *
 * @param x
 *   The integer value to align
 *
 * @return
 *   Input parameter aligned to the next power of 2
 */
static inline uint32_t __cuckoo_hash_align32pow2(uint32_t x)
{
	x--;
	x = __cuckoo_hash_combine32ms1b(x);

	return x + 1;
}

/* Structure that stores key-value pair */
struct __cuckoo_hash_key {
	/* Constant value size */
	char value[CUCKOO_HASH_VALUE_SIZE];
	/* Variable key size */
	char key[0];
};

#define CUCKOO_HASH_CACHE_LINE_SIZE 64

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

/*
 * Table storing all different key compare functions
 */
const __cuckoo_hash_cmp_eq_t __cuckoo_hash_cmp_jump_table[NUM_KEY_CMP_CASES] = {
	NULL, __cuckoo_hash_k16_cmp_eq, memcmp
};
#else
/*
 * Table storing all different key compare functions
 */
const __cuckoo_hash_cmp_eq_t __cuckoo_hash_cmp_jump_table[NUM_KEY_CMP_CASES] = {
	NULL, memcmp
};

#endif

static inline int __cuckoo_hash_cmp_eq(const void *key1, const void *key2,
				       struct cuckoo_hash *h)
{
	return __cuckoo_hash_cmp_jump_table[h->cmp_jump_table_idx](key1, key2,
								   h->key_len);
}

#define CUCKOO_HASH_EMPTY_SLOT 0

/**
 * add a byte-value offset to a pointer
 */
#define CUCKOO_HASH_PTR_ADD(ptr, x) ((void *)((uintptr_t)(ptr) + (x)))

static int
__cuckoo_hash_validate_parameters(struct cuckoo_hash_parameters *params)
{
	int ret = 0;

	if (params == NULL) {
		cuckoo_log(err, "%s: has no parameters\n", __func__);
		ret = -EINVAL;
		goto out;
	}

	if (params->entries > CUCKOO_HASH_ENTRIES_MAX ||
	    params->entries < CUCKOO_HASH_BUCKET_ENTRIES ||
	    params->key_len == 0) {
		cuckoo_log(err, "%s: has invalid parameters\n", __func__);
		ret = -EINVAL;
		goto out;
	}

	if (params->extra_flag & ~CUCKOO_HASH_EXTRA_FLAGS_MASK) {
		cuckoo_log(err, "%s: unsupported extra flags\n", __func__);
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
	params->entries = attr->max_entries;
	params->key_len = attr->key_size;
	params->hash_func_init_val = CUCKOO_HASH_SEED;
	params->extra_flag = 0;
}

static int cuckoo_hash_alloc_check(union bpf_attr *attr)
{
	struct cuckoo_hash_parameters params;
	int ret;

	// Check basic attributes
	if (attr->value_size != CUCKOO_HASH_VALUE_SIZE) {
		cuckoo_log(err,
			   "value_size (%d) != CUCKOO_HASH_VALUE_SIZE (%d)\n",
			   attr->value_size, CUCKOO_HASH_VALUE_SIZE);
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
	struct __cuckoo_hash_free_slot *free_slots = NULL, *slot = NULL;
	void *keys = NULL;
	void *buckets = NULL;
	unsigned num_key_slots;
	uint32_t i, num_buckets;
	int ret;
	__cuckoo_hash_function default_hash_func;

	if ((ret = __cuckoo_hash_validate_parameters(params)) != 0) {
		goto out;
	}

	num_key_slots = params->entries + 1;

	/* Create free slot store (Dummy slot index is not enqueued) */
	free_slots = (struct __cuckoo_hash_free_slot *)kvzalloc(
		sizeof(struct __cuckoo_hash_free_slot) * num_key_slots,
		GFP_USER | __GFP_NOWARN);
	if (free_slots == NULL) {
		cuckoo_log(err, "free slot store memory allocation failed\n");
		ret = -ENOMEM;
		goto out;
	}

	num_buckets = __cuckoo_hash_align32pow2(params->entries) /
		      CUCKOO_HASH_BUCKET_ENTRIES;

	buckets = kvzalloc(num_buckets * sizeof(struct __cuckoo_hash_bucket),
			   GFP_USER | __GFP_NOWARN);
	if (buckets == NULL) {
		cuckoo_log(err, "buckets memory allocation failed\n");
		ret = -ENOMEM;
		goto out_free_free_slots;
	}

	const uint32_t key_entry_size = CUCKOO_HASH_ALIGN(
		sizeof(struct __cuckoo_hash_key) + params->key_len,
		CUCKOO_HASH_KEY_ALIGNMENT);
	const uint64_t key_tbl_size = (uint64_t)key_entry_size * num_key_slots;

	keys = kvzalloc(key_tbl_size, GFP_USER | __GFP_NOWARN);
	if (keys == NULL) {
		cuckoo_log(err, "key table memory allocation failed\n");
		ret = -ENOMEM;
		goto out_free_buckets;
	}

	/*
	 * If x86 architecture is used, select appropriate compare function,
	 * which may use x86 intrinsics, otherwise use memcmp
	 */
	/* Select function to compare keys */
	switch (params->key_len) {
#ifdef CUCKOO_HASH_SIMD
	case 16:
		h->cmp_jump_table_idx = KEY_16_BYTES;
		cuckoo_log(debug, "using SIMD to compare keys (of 16B)\n");
		break;
#endif
	default:
		/* If key is not multiple of 16, use generic memcmp */
		h->cmp_jump_table_idx = KEY_OTHER_BYTES;
	}

	/* Default hash function */
	default_hash_func = (__cuckoo_hash_function)__cuckoo_hash_hash_default;
	/* Setup hash context */
	h->entries = params->entries;
	h->key_len = params->key_len;
	h->key_entry_size = key_entry_size;
	h->hash_func_init_val = params->hash_func_init_val;
	h->num_buckets = num_buckets;
	h->bucket_bitmask = h->num_buckets - 1;
	h->buckets = buckets;
	h->hash_func = default_hash_func;
	h->key_store = keys;
	h->free_slot_store = free_slots;

#ifdef CUCKOO_HASH_SIMD
	h->sig_cmp_fn = CUCKOO_HASH_COMPARE_SSE;
#else
	h->sig_cmp_fn = CUCKOO_HASH_COMPARE_SCALAR;
#endif

	INIT_LIST_HEAD(&h->free_slot_list);
	h->free_slot_store[0].list.next = LIST_POISON1;
	h->free_slot_store[0].list.prev = LIST_POISON2;
	/* Populate free slots list (queue). Entry zero is reserved for key misses. */
	for (i = 1; i < num_key_slots; i++) {
		slot = h->free_slot_store + i;
		slot->slot_id = i;
		// cuckoo_log(debug, "adding slot %d at %x\n", slot->slot_id, slot);
		list_add_tail(&slot->list, &h->free_slot_list);
	}

	goto out;

out_free_keys:
	kvfree(keys);
	keys = NULL;
out_free_buckets:
	kvfree(buckets);
	buckets = NULL;
out_free_free_slots:
	kvfree(free_slots);
	free_slots = NULL;
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
	if (h->buckets != NULL) {
		kvfree(h->buckets);
	}
	if (h->free_slot_store != NULL) {
		kvfree(h->free_slot_store);
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
	return hash & h->bucket_bitmask;
}

static inline uint32_t __cuckoo_hash_get_alt_bucket_index(struct cuckoo_hash *h,
							  uint32_t cur_bkt_idx,
							  uint16_t sig)
{
	return (cur_bkt_idx ^ sig) & h->bucket_bitmask;
}

/* Search one bucket to find the match key - uses rw lock */
static inline int32_t
__cuckoo_hash_search_one_bucket(struct cuckoo_hash *h, const void *key,
				uint16_t sig, void **data,
				const struct __cuckoo_hash_bucket *bkt)
{
	int i;
	struct __cuckoo_hash_key *k, *keys = h->key_store;

	for (i = 0; i < CUCKOO_HASH_BUCKET_ENTRIES; i++) {
		if (bkt->sig_current[i] == sig &&
		    bkt->key_idx[i] != CUCKOO_HASH_EMPTY_SLOT) {
			k = (struct __cuckoo_hash_key
				     *)((char *)keys +
					bkt->key_idx[i] * h->key_entry_size);

			if (__cuckoo_hash_cmp_eq(key, k->key, h) == 0) {
				if (data != NULL)
					*data = &k->value;
				/*
				 * Return index where key is stored,
				 * subtracting the first dummy index
				 */
				return bkt->key_idx[i] - 1;
			}
		}
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
	return h->hash_func(key, h->key_len, h->hash_func_init_val);
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

	for (i = 0; i < CUCKOO_HASH_BUCKET_ENTRIES; i++) {
		if (bkt->sig_current[i] == sig) {
			k = (struct __cuckoo_hash_key
				     *)((char *)keys +
					bkt->key_idx[i] * h->key_entry_size);
			if (__cuckoo_hash_cmp_eq(key, k->key, h) == 0) {
				memcpy(&k->value, data, CUCKOO_HASH_VALUE_SIZE);
				/*
				 * Return index where key is stored,
				 * subtracting the first dummy index
				 */
				return bkt->key_idx[i] - 1;
			}
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

	new_k = CUCKOO_HASH_PTR_ADD(keys, slot_id * h->key_entry_size);
	memcpy(&new_k->value, data, CUCKOO_HASH_VALUE_SIZE);
	/* Copy key */
	memcpy(new_k->key, key, h->key_len);

	/* Find an empty slot and insert */
	ret = __cuckoo_hash_cuckoo_insert_mw(h, prim_bkt, sec_bkt, key, data,
					     short_sig, slot_id, &ret_val);
	cuckoo_log(debug, "prim bucket insert: %d\n", ret);
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
	u64 size = 0, num_key_slots = cuckoo_hash->entries + 1;

	size += sizeof(*map);
	size += (sizeof(*cuckoo_hash) +
		 sizeof(cuckoo_hash->free_slot_store[0]) * num_key_slots +
		 sizeof(cuckoo_hash->buckets[0]) * cuckoo_hash->num_buckets +
		 cuckoo_hash->key_entry_size * num_key_slots) *
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
#ifdef CUCKOO_HASH_SIMD
	/* make this structure 16 bytes to use __cuckoo_hash_k16_cmp_eq */
	uint8_t pad[3];
#endif
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
	attr.max_entries = 32;

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

	struct pkt_5tuple keys[40];
	uint32_t values[40];
	get_random_bytes(keys, sizeof(keys));
	get_random_bytes(values, sizeof(values));

	for (int i = 0; i < 32; ++i) {
		preempt_disable();
		ret = cuckoo_hash_update_elem(map, keys + i, values + i,
					      BPF_ANY);
		preempt_enable();
		cuckoo_log(debug, "testing i = %d\n", i);
		lkm_assert_eq(0, ret, "cuckoo_hash_lookup_elem should succeed");

		preempt_disable();
		data = cuckoo_hash_lookup_elem(map, keys + i);
		preempt_enable();
		lkm_assert_eq(0, IS_ERR_OR_NULL(data),
			      "cuckoo_hash_lookup_elem should succeed");
		lkm_assert_eq(
			values[i], *data,
			"cuckoo_hash_lookup_elem should return correct value");
	}
	for (int i = 32; i < 40; ++i) {
		preempt_disable();
		ret = cuckoo_hash_update_elem(map, keys + i, values + i,
					      BPF_ANY);
		preempt_enable();
		cuckoo_log(debug, "testing i = %d\n", i);
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
