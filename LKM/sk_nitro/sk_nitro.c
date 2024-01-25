#include <linux/errno.h>
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

#include "sk_nitro.h"
#include "fasthash.h"
#include "fasthash_simd.h"
#include "xxhash_simd.h"

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

#define SK_NITRO_UPDATE_PROB_PERCENT 10
#include "geo_sampling_pool.h"

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

#if USE_HASH32
static __always_inline __m256i hash_func_pkts(const __m256i *b0,
					      const __m256i *b1,
					      const __m256i *b2,
					      const __m256i *b3, u32 seed)
{
	return xxh32_avx2_pkt5_pkts(b0, b1, b2, b3, seed);
}

#else
static __always_inline __m256i hash_func_pkts(const __m256i *low,
					      const __m256i *high, u32 seed)
{
	return _fasthash64_avx2_pkt5_pkts(low, high, seed);
}

#endif

struct pkt_5tuple {
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	uint8_t proto;
} __attribute__((packed));

typedef struct pkt_5tuple raw_skp_key_type;

static int raw_sketch_primitive_alloc_check(u32 key_size)
{
	if (key_size != sizeof(raw_skp_key_type))
		return -EINVAL;
	return 0;
}

/***********************cache_raw_sketch_primitive****************/

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
			__m256i hh = hash_func_batch(
				pkt, sizeof(struct pkt_5tuple), &simd_seeds[i]);
#pragma GCC unroll 8
			for (j = 0; j < _HASH_BATCH_SIZE; j++) {
				index = *((u32 *)&hh + j) & (COLUMNS - 1);
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

/***********************************************************************/
/******************************cache_rr_sketch_primitive*****************/
/***********************************************************************/

#if USE_SIMD

#if USE_HASH32

#define PKT_BATCH_SIZE_SHIFT 3 /* BATCH_SIZE 8, 256 / 32 = 8*/

#else

#define PKT_BATCH_SIZE_SHIFT 2 /* BATCH_SIZE 4, 256 / 64 = 4*/

#endif

#define PKT_BATCH_SIZE (1 << (PKT_BATCH_SIZE_SHIFT))
#define PKT_BATCH_NUM (ROW_SIMD_CACHE_PKTS >> (PKT_BATCH_SIZE_SHIFT))

struct pkts_vec {
	/*padding pkt5_tuple to 16bytes*/
#if USE_HASH32
	__m256i vec[4];
#else
	__m256i vec[2];
#endif
};

struct row_pkts_cache {
	//struct pkt_5tuple_cache_value data[ROW_SIMD_CACHE_PKTS];
	struct pkts_vec data[PKT_BATCH_NUM];
	int num;
};

struct crrskp_row {
	__sk_elem array[COLUMNS];
	struct row_pkts_cache cache;
};

struct cache_row_raw_skp_map {
	struct crrskp_row __percpu *rows[HASHFN_N];
};

/*
 *@batch_idx: idx in batch
 */
#if USE_HASH32
static __always_inline void ins_pkts_vec(raw_skp_key_type *key, __m256i *b0,
					 __m256i *b1, __m256i *b2, __m256i *b3,
					 int batch_idx)
{
	*((u32 *)b0 + batch_idx) = *((u32 *)key);
	*((u32 *)b1 + batch_idx) = *((u32 *)key + 1);
	*((u32 *)b2 + batch_idx) = *((u32 *)key + 2);
	*((u32 *)b3 + batch_idx) = 0;
	memcpy((u32 *)b3 + batch_idx, (u32 *)key + 3, 1);
}
#else
static __always_inline void ins_pkts_vec(raw_skp_key_type *key, __m256i *low,
					 __m256i *high, int batch_idx)
{
	*((u64 *)low + batch_idx) = *((u64 *)key);
	*((u64 *)high + batch_idx) = 0;
	memcpy((u64 *)high + batch_idx, (u64 *)key + 1, 5);
}
#endif

static int cache_row_raw_skp_alloc_check(u32 key_size)
{
	return raw_sketch_primitive_alloc_check(key_size);
}

void crrskp_free_rows(struct cache_row_raw_skp_map *crrskp)
{
	int i;
	for (i = 0; i < HASHFN_N; i++) {
		if (crrskp->rows[i] != NULL)
			free_percpu(crrskp->rows[i]);
	}
}

static void *cache_row_raw_skp_alloc(void)
{
	struct cache_row_raw_skp_map *crrskp;
	int cpu;
	int i;
	crrskp = kmalloc(sizeof(*crrskp), GFP_KERNEL);
	if (crrskp == NULL)
		return ERR_PTR(-ENOMEM);
	memset(crrskp, 0, sizeof(*crrskp));
	for (i = 0; i < HASHFN_N; i++) {
		/*alloc and init row*/
		crrskp->rows[i] = alloc_percpu(struct crrskp_row);
		if (crrskp->rows[i] == NULL) {
			kfree(crrskp);
			crrskp_free_rows(crrskp);
			return ERR_PTR(-ENOMEM);
		}
		for_each_possible_cpu(cpu) {
			memset(per_cpu_ptr(crrskp->rows[i], cpu), 0,
			       sizeof(struct crrskp_row));
		}
	}

	return (void *)(crrskp);
}

static void cache_row_raw_skp_free(struct cache_row_raw_skp_map *crrskp)
{
	crrskp_free_rows(crrskp);
	kfree(crrskp);
}

static __always_inline int
__cache_row_raw_skp_update_elem(struct cache_row_raw_skp_map *crrskp,
				raw_skp_key_type *key, int row_to_update)
{
	struct crrskp_row *row;
	int batch_idx, batch_num_idx;
	int b, j, num;
	u32 index;
	struct pkts_vec *vec;

	if (unlikely(row_to_update >= HASHFN_N || row_to_update < 0)) {
		return -EINVAL;
	}

#if PRINT_HASH_TIME
	u64 start, end;
#endif

	row = this_cpu_ptr(crrskp->rows[row_to_update]);
	num = row->cache.num;
	batch_num_idx = num >> PKT_BATCH_SIZE_SHIFT;
	batch_idx = num & (PKT_BATCH_SIZE - 1);
	row->cache.num = ++num;
	vec = &(row->cache.data[batch_num_idx]);
#if USE_HASH32
	ins_pkts_vec(key, &(vec->vec[0]), &(vec->vec[1]), &(vec->vec[2]),
		     &(vec->vec[3]), batch_idx);

#else
	ins_pkts_vec(key, &(vec->vec[0]), &(vec->vec[1]), batch_idx);
#endif

	if (num < ROW_SIMD_CACHE_PKTS) {
		//pr_info("cache row in cache %d\n", num);
		return CRSKP_IN_CACHE;
	}

	/*cache full, use simd cacluatinig hashes*/
#if PRINT_HASH_TIME
	start = ktime_get_mono_fast_ns();
#endif
	kernel_fpu_begin();

#pragma GCC unroll 8
	for (b = 0; b < PKT_BATCH_NUM; b++) {
		vec = &(row->cache.data[b]);
		/*iteratr each batch*/
#if USE_HASH32
		__m256i hh = hash_func_pkts(&(vec->vec[0]), &(vec->vec[1]),
					    &(vec->vec[2]), &(vec->vec[3]),
					    seeds[row_to_update]);

#else
		__m256i hh = hash_func_pkts(&(vec->vec[0]), &(vec->vec[1]),
					    seeds[row_to_update]);
#endif
#pragma GCC unroll 4
		for (j = 0; j < PKT_BATCH_SIZE; j++) {
#if USE_HASH32
			index = *((u32 *)&hh + j) & (COLUMNS - 1);
#else
			/*TODO: use both high and low parts of 64hash*/
			index = (u32) * ((u64 *)&hh + j) & (COLUMNS - 1);
#endif
			row->array[index] += 1;
		}
	}
	kernel_fpu_end();

#if PRINT_HASH_TIME
	end = ktime_get_mono_fast_ns();
#endif

#if PRINT_HASH_TIME
	pr_info("cach row raw skp simd hash time used %llu\n", end - start);
#endif
	row->cache.num = 0;
	return 0;
}

#endif

/*********************************************************
 * ************BPF_MAP IMPL*******************************
 * *******************************************************/

#define GEO_SAMPLING_MASK (MAX_GEOSAMPLING_SIZE - 1)

struct geo_sampling_ctx {
	u32 cnt;
	u32 geo_sampling_idx ____cacheline_aligned;
	u32 pool[MAX_GEOSAMPLING_SIZE] ____cacheline_aligned;
};

static void init_geo_sampling_pool(struct geo_sampling_ctx *ctx, int cpu)
{
	/*init*/
	ctx->geo_sampling_idx = 0;
	ctx->cnt = 0;
	if (cpu >= ONLINE_CPU_NUM) {
		/*TODO: currently we only provide online cpu's data*/
		//memset(__geo_sampling_pool, 0, sizeof(u32) * MAX_GEOSAMPLING_SIZE);
		memset(ctx->pool, 0, sizeof(u32) * MAX_GEOSAMPLING_SIZE);
	} else {
		memcpy(ctx->pool, GEO_SAMPLING_POOL[cpu],
		       sizeof(u32) * MAX_GEOSAMPLING_SIZE);
	}
}

static __always_inline u32 gen_geo_cnt(struct geo_sampling_ctx *ctx)
{
	uint32_t geo_value_idx = ctx->geo_sampling_idx;
	geo_value_idx = (geo_value_idx + 1) & GEO_SAMPLING_MASK;
	ctx->geo_sampling_idx = geo_value_idx;
	return ctx->pool[geo_value_idx];
};

/**********NITRO SKETCH KERENL MODUEL IMPL***************/

struct sketch_nitro_map {
	struct cache_row_raw_skp_map *crrskp;
	struct geo_sampling_ctx __percpu *geo_ctx;
};

static int sketch_nitro_alloc_check(union bpf_attr *attr)
{
	return cache_row_raw_skp_alloc_check(attr->key_size);
}

static struct bpf_map *sketch_nitro_alloc(union bpf_attr *attr)
{
	void *map;
	int cpu;
	struct sketch_nitro_map *nitro;
	nitro = kmalloc(sizeof(*nitro), GFP_KERNEL);
	if (nitro == NULL)
		return ERR_PTR(-ENOMEM);
	memset(nitro, 0, sizeof(*nitro));

	/*init geo*/
	nitro->geo_ctx = alloc_percpu(struct geo_sampling_ctx);
	if (nitro->geo_ctx == NULL) {
		map = ERR_PTR(-ENOMEM);
		goto free_nitro;
	}

	for_each_possible_cpu(cpu) {
		init_geo_sampling_pool(per_cpu_ptr(nitro->geo_ctx, cpu), cpu);
	}

	map = nitro->crrskp = cache_row_raw_skp_alloc();
	if (IS_ERR(map))
		goto free_geo_ctx;

	return (void *)nitro;

free_geo_ctx:;
	free_percpu(nitro->geo_ctx);

free_nitro:;
	kfree(nitro);
	return map;
}

static void sketch_nitro_free(struct bpf_map *map)
{
	struct sketch_nitro_map *nitro = (struct sketch_nitro_map *)map;
	free_percpu(nitro->geo_ctx);
	cache_row_raw_skp_free(nitro->crrskp);
	kfree(nitro);
}

static long sketch_nitro_update_elem(struct bpf_map *map, void *key,
				     void *value, u64 flag)
{
	/*for each rows:
	 * 1. generate geo ctx
	 * 2. selectively update row of skp
	 */
	struct sketch_nitro_map *nitro = (struct sketch_nitro_map *)map;
	int i, res;
	u32 row_to_update, next_geo_value;
	struct geo_sampling_ctx *geo_ctx;
	geo_ctx = this_cpu_ptr(nitro->geo_ctx);
	if (geo_ctx->cnt >= HASHFN_N) {
		/*skip this update*/
		geo_ctx->cnt -= HASHFN_N;
		return 0;
	}
	row_to_update = geo_ctx->cnt;
	for (i = 0; i < HASHFN_N; i++) {
		res = __cache_row_raw_skp_update_elem(
			nitro->crrskp, (raw_skp_key_type *)key,
			row_to_update & (HASHFN_N - 1));
		if (unlikely(res < 0)) {
			pr_err("nitro failed to update to row skp\n");
		}

		next_geo_value = gen_geo_cnt(geo_ctx);
		row_to_update += next_geo_value;
		if (row_to_update >= HASHFN_N)
			break;
	}
	if (unlikely(next_geo_value == 0)) {
		pr_err("gen_geo_cnt renturn zero, should not happen\n");
		return -EFAULT;
	} else {
		geo_ctx->cnt = next_geo_value - 1;
	}
	return 0;
}

static u64 sketch_nito_mem_usage(const struct bpf_map *map)
{
	return 0;
}

static struct bpf_map_ops sketch_nitro_ops = {
	.map_alloc = sketch_nitro_alloc,
	.map_alloc_check = sketch_nitro_alloc_check,
	.map_free = sketch_nitro_free,
	.map_update_elem = sketch_nitro_update_elem,
	.map_mem_usage = sketch_nito_mem_usage,
};

static int __init sketch_lib_exp_init(void)
{
	init_simd_seeds();
	init_hash_constants();
	pr_info("sketch_lib_exp  module init");
	return bpf_register_static_cmap(&sketch_nitro_ops, THIS_MODULE);
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
