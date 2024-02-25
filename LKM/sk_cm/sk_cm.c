#include <linux/init.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/bpf.h>
#include <linux/bpf_custom_map.h>
#include <linux/string.h>
#include <linux/math.h>
#include <linux/log2.h>
#include <linux/xxhash.h>
#include <linux/minmax.h>

#include "sk_cm.h"
#include "fasthash.h"
#include "fasthash_simd.h"
#include "xxhash_simd.h"
#include "crc.h"

#define _CS_ROWS 8
#define _CS_COLUMNS 256
#define _NM_LAYERS 32
#define HASHFN_N _CS_ROWS
#define COLUMNS _CS_COLUMNS
#define _HEAP_SIZE 32
#define USE_BITMAP_CACHE 0
#define USE_SIMD 1
#define _HASH_BATCH_SIZE 8
#define _HASH_BATCH_NUM \
	(HASHFN_N / _HASH_BATCH_SIZE + !!(HASHFN_N % _HASH_BATCH_SIZE))
#define _HASH_ARRAY_SIZE (8 * _HASH_BATCH_NUM)
#define PRINT_HASH_TIME 0
#define USE_PKT5_HASH 1
#define SIMD_CACHE_PKTS 64 /*used for CACHE_RAW_SKP*/
#define ROW_SIMD_CACHE_PKTS 64 /*used for CACHE_ROW_RAW_SKP*/
#define USE_XXHASH 1 /*switch between fasthash and xx hash*/
#define USE_HASH32 1 /*used for CACHE_ROW_RAW_SKP*/

#define SKP_ROW_SIZE sizeof(__sk_elem[COLUMNS])
#define SKP_SIZE sizeof(__sk_elem[HASHFN_N][COLUMNS])

#if HASHFN_N <= 2
#define USE_CRC
#endif

extern int bpf_register_static_cmap(struct bpf_map_ops *map,
				    struct module *onwer);
extern void bpf_unregister_static_cmap(struct module *onwer);
extern void bpf_map_area_free(void *area);
extern void *bpf_map_area_alloc(u64 size, int numa_node);

typedef struct pkt_5tuple raw_skp_key_type;

const u32 seeds[] = {
	0xec5853, 0xec5859, 0xec5861, 0xec587f, 0xec58a7, 0xec58b3, 0xec58c7,
	0xec58d1, 0xec5853, 0xec5859, 0xec5861, 0xec587f, 0xec58a7, 0xec58b3,
	0xec58c7, 0xec58d1, 0xec5853, 0xec5859, 0xec5861, 0xec587f, 0xec58a7,
	0xec58b3, 0xec58c7, 0xec58d1, 0xec5853, 0xec5859, 0xec5861, 0xec587f,
	0xec58a7, 0xec58b3, 0xec58c7, 0xec58d1, 0xec5853, 0xec5859, 0xec5861,
	0xec587f, 0xec58a7, 0xec58b3, 0xec58c7, 0xec58d1, 0xec5853, 0xec5859,
	0xec5861, 0xec587f, 0xec58a7, 0xec58b3, 0xec58c7, 0xec58d1, 0xec5853,
	0xec5859, 0xec5861, 0xec587f, 0xec58a7, 0xec58b3, 0xec58c7, 0xec58d1,
	0xec5853, 0xec5859, 0xec5861, 0xec587f, 0xec58a7, 0xec58b3, 0xec58c7,
	0xec58d1,
};

static __m256i simd_seeds[_HASH_BATCH_NUM];

static __always_inline void init_simd_seeds(void)
{
	int i;
	u32 *__seeds;
	for (i = 0; i < _HASH_BATCH_NUM; i++) {
		__seeds = (u32 *)seeds + i * 8;
		simd_seeds[i] = _mm256_loadu_si256((const __m256i_u *)__seeds);
	}
}

static __always_inline void init_hash_constants(void)
{
#if USE_XXHASH || USE_HASH32
	xxh_init();
#endif
#if !USE_XXHASH || !USE_HASH32
	fasthash_init();
#endif
}

static __always_inline __m256i hash_func_batch(const void *input, size_t length,
					       const __m256i *seeds)
{
#if USE_XXHASH

#if USE_PKT5_HASH
	return xxh32_avx2_pkt5(input, seeds);
#else
#error Generalized SIMD xxHash has not been implemented yet
#endif

#else

#if USE_PKT5_HASH
	return _fasthash64_avx2_pkt5(input, seeds);
#else
	return _fasthash64_avx2(input, length, seeds);
#endif

#endif
}

/***********************cache_raw_sketch_primitive****************/

struct pkt_5tuple {
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	uint8_t proto;
} __attribute__((packed));

struct pkt_5tuple_cache_value {
	struct pkt_5tuple pkt ____cacheline_aligned;
	__sk_elem value;
} __attribute__((aligned(8)));

struct pkts_cache {
	struct pkt_5tuple_cache_value data[SIMD_CACHE_PKTS];
	__u32 num;
};

struct cache_raw_sketch_primitive_map {
	struct bpf_map map;
	__sk_elem __percpu *arrays;
	struct pkts_cache __percpu *cache;
};

static int cache_raw_sketch_primitive_alloc_check(u32 key_size)
{
	if (key_size != sizeof(raw_skp_key_type))
		return -EINVAL;
	return 0;
}

static void *cache_raw_sketch_primitive_alloc(void)

{
	struct cache_raw_sketch_primitive_map *crskp;
	int cpu;
	crskp = kmalloc(sizeof(*crskp), GFP_KERNEL);
	if (crskp == NULL)
		return ERR_PTR(-ENOMEM);
	memset(crskp, 0, sizeof(*crskp));
	crskp->arrays = (__sk_elem __percpu *)__alloc_percpu(SKP_SIZE,
							     __alignof__(u64));
	if (crskp->arrays == NULL) {
		kfree(crskp);
		return ERR_PTR(-ENOMEM);
	};

	for_each_possible_cpu(cpu) {
		memset(per_cpu_ptr(crskp->arrays, cpu), 0, SKP_SIZE);
	}

	crskp->cache = alloc_percpu(struct pkts_cache);
	if (crskp->cache == NULL) {
		free_percpu(crskp->arrays);
		kfree(crskp);
		return ERR_PTR(-ENOMEM);
	}
	for_each_possible_cpu(cpu) {
		memset(per_cpu_ptr(crskp->cache, cpu), 0,
		       sizeof(struct pkts_cache));
	}
	return (void *)crskp;
}

static void
cache_raw_sketch_primitive_free(struct cache_raw_sketch_primitive_map *crskp)
{
	free_percpu(crskp->arrays);
	free_percpu(crskp->cache);
	kfree(crskp);
}

#define CRSKP_IN_CACHE 1

static __always_inline struct pkts_cache *
__cache_raw_sketch_lookup_elem(struct cache_raw_sketch_primitive_map *crskp)
{
	struct pkts_cache *cache = this_cpu_ptr(crskp->cache);
	return cache;
}

static __always_inline int __cache_raw_sketch_primitive_update_elem(
	struct cache_raw_sketch_primitive_map *crskp, raw_skp_key_type *key)
{
	__sk_elem *arrays = this_cpu_ptr(crskp->arrays);
	struct pkts_cache *cache = this_cpu_ptr(crskp->cache);
	int i;
	u32 index;
	struct pkt_5tuple *pkt;
#if PRINT_HASH_TIME
	u64 start;
	u64 end;
#endif
	int j, p;
	int row;
	u32 num;

	num = cache->num;
	memcpy(&(cache->data[num++]), key, sizeof(*key));
	cache->num = num;

	if (num < SIMD_CACHE_PKTS) {
		/*just cache 5tuple*/
		return CRSKP_IN_CACHE;
	}

	/*cache full, use simd cacluatinig hashes*/

#if USE_SIMD == 1

#if PRINT_HASH_TIME
	start = ktime_get_mono_fast_ns();
#endif
	kernel_fpu_begin();
	for (p = 0; p < SIMD_CACHE_PKTS; p++) {
		row = 0;
		//memcpy(&pkt, (struct pkt_5tuple*)(&cache->data[p]), sizeof(struct pkt_5tuple));
		pkt = (struct pkt_5tuple *)(&cache->data[p]);
#pragma GCC unroll 8
		for (i = 0; i < _HASH_BATCH_NUM; i++) {
#ifndef USE_CRC
			__m256i hh = hash_func_batch(
				pkt, sizeof(struct pkt_5tuple), &simd_seeds[i]);
#endif /* USE_CRC */
#pragma GCC unroll 8
			for (j = 0; j < _HASH_BATCH_SIZE; j++) {
#ifdef USE_CRC
				index = crc32c(pkt, sizeof(*pkt),
					       *(seeds + i * 8 + j)) &
					(COLUMNS - 1);
#else
				index = *((u32 *)&hh + j) & (COLUMNS - 1);
#endif /* USE_CRC */
				*(arrays + row * COLUMNS + index) += 1;
				row += 1;
			}
		}
	}
	kernel_fpu_end();

#if PRINT_HASH_TIME
	end = ktime_get_mono_fast_ns();
#endif

#if PRINT_HASH_TIME
	pr_info("cach skp simd hash time used %llu\n", end - start);
#endif

#else

#if PRINT_HASH_TIME
	start = ktime_get_mono_fast_ns();
#endif
	for (p = 0; p < SIMD_CACHE_PKTS; p++) {
		pkt = (struct pkt_5tuple *)(&cache->data[p]);
//struct pkt_5tuple *pkt = (struct pkt_5tuple*)(&cache->data[p]);
#pragma GCC unroll 64
		for (i = 0; i < HASHFN_N; i++) {
			index = hash_func(pkt, sizeof(struct pkt_5tuple),
					  seeds[i]) &
				(COLUMNS - 1);
			*(arrays + i * COLUMNS + index) += 1;
		}
	}

#if PRINT_HASH_TIME
	end = ktime_get_mono_fast_ns();
#endif

#if PRINT_HASH_TIME
	pr_info("cach skp hash time used %llu\n", end - start);
#endif

#endif
	cache->num = 0;
	return 0;
}

/*********************************************************
 * ************BPF_MAP IMPL*******************************
 * *******************************************************/

/***********************cache raw skp***************/
static int cache_raw_skp_alloc_check(union bpf_attr *attr)
{
	return cache_raw_sketch_primitive_alloc_check(attr->key_size);
}

static struct bpf_map *cache_raw_skp_alloc(union bpf_attr *attr)
{
	return cache_raw_sketch_primitive_alloc();
}

static void cache_raw_skp_free(struct bpf_map *map)
{
	cache_raw_sketch_primitive_free(
		(struct cache_raw_sketch_primitive_map *)map);
}

static long cache_raw_skp_update_elem(struct bpf_map *map, void *key,
				      void *value, u64 flag)
{
	return __cache_raw_sketch_primitive_update_elem(
		(struct cache_raw_sketch_primitive_map *)map, key);
}

static u64 cache_raw_skp_map_mem_usage(const struct bpf_map *map)
{
	return 0;
}

static struct bpf_map_ops cache_raw_skp_ops = {
	.map_alloc = cache_raw_skp_alloc,
	.map_alloc_check = cache_raw_skp_alloc_check,
	.map_free = cache_raw_skp_free,
	.map_update_elem = cache_raw_skp_update_elem,
	.map_mem_usage = cache_raw_skp_map_mem_usage,
};

/************************* kfuncs **************************/

#define NO_TEAR_ADD(x, val) WRITE_ONCE((x), READ_ONCE(x) + (val))

__bpf_kfunc void bpf_countmin_add_avx2_pkt5(const struct pkt_5tuple *buf,
					    const u32 *seeds, u32 *values)
{
#ifndef USE_CRC
	const __m256i seeds_vec = _mm256_loadu_si256((const __m256i_u *)seeds);
	const __m256i hashes_vec = _fasthash64_avx2_pkt5(buf, &seeds_vec);
	const u32 *hashes = (const u32 *)&hashes_vec;
#endif /* USE_CRC */

	for (int i = 0; i < HASHFN_N; i++) {
#ifdef USE_CRC
		u32 target_idx = crc32c(buf, sizeof(*buf), seeds[i]) &
				 (COLUMNS - 1);
#else
		u32 target_idx = hashes[i] & (COLUMNS - 1);
#endif /* USE_CRC */
		NO_TEAR_ADD(*(values + i * COLUMNS + target_idx), 1);
	}
}
EXPORT_SYMBOL_GPL(bpf_countmin_add_avx2_pkt5);

BTF_SET8_START(sk_cm_kfunc_ids)
BTF_ID_FLAGS(func, bpf_countmin_add_avx2_pkt5)
BTF_SET8_END(sk_cm_kfunc_ids)

static const struct btf_kfunc_id_set sk_cm_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &sk_cm_kfunc_ids,
};

static int register_kfuncs(void)
{
	int ret;
	if ((ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
					     &sk_cm_kfunc_set)) != 0) {
		pr_err("sk_cm: failed to register kfuncs: %d\n", ret);
		return ret;
	}

	return 0;
}

static int __init sketch_lib_exp_init(void)
{
	init_simd_seeds();
	init_hash_constants();
	register_kfuncs();
	pr_info("sketch_lib_exp  module init");
	return bpf_register_static_cmap(&cache_raw_skp_ops, THIS_MODULE);
}

static void __exit sketch_lib_exp_exit(void)
{
	pr_info("sketch_lib_exp module exit");
	bpf_unregister_static_cmap(THIS_MODULE);
	return;
}

/* Register module functions */
module_init(sketch_lib_exp_init);
module_exit(sketch_lib_exp_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chonepieceyb");
MODULE_DESCRIPTION("sketch lib");
MODULE_VERSION("0.01");
