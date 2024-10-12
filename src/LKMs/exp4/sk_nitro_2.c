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
#include <linux/minmax.h>
#include <linux/min_heap.h>
#include <linux/hash.h>
#include <linux/container_of.h>

#include "crc.h"

/**********************************************************
 * ************SKETCH PRIMITIVE STRUCT DEFINE*************
 * *******************************************************/

typedef u32 __sk_elem;

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

#define SK_NITRO_UPDATE_PROB_PERCENT 2
#include "geo_sampling_pool.h"

extern int bpf_register_static_cmap(struct bpf_map_ops *map,
				    struct module *onwer);
extern void bpf_unregister_static_cmap(struct module *onwer);
extern void bpf_map_area_free(void *area);
extern void *bpf_map_area_alloc(u64 size, int numa_node);

typedef struct pkt_5tuple raw_skp_key_type;
typedef typeof(GEO_SAMPLING_POOL[0][0]) geo_cnt_t;

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

struct pkt_5tuple {
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	uint8_t proto;
} __attribute__((packed));

typedef struct pkt_5tuple raw_skp_key_type;

/*********************************************************
 * ************BPF_MAP IMPL*******************************
 * *******************************************************/

#define GEO_SAMPLING_MASK (MAX_GEOSAMPLING_SIZE - 1)

struct geo_sampling_ctx {
	geo_cnt_t cnt;
	u32 geo_sampling_idx ____cacheline_aligned;
	geo_cnt_t (*pool)[MAX_GEOSAMPLING_SIZE] ____cacheline_aligned;
};

static geo_cnt_t empty_geo_cnts[MAX_GEOSAMPLING_SIZE] = { 0 };

static void init_geo_sampling_pool(struct geo_sampling_ctx *ctx, int cpu)
{
	/*init*/
	ctx->geo_sampling_idx = 0;
	ctx->cnt = 0;
	if (cpu >= ONLINE_CPU_NUM) {
		/*TODO: currently we only provide online cpu's data*/
		ctx->pool = &empty_geo_cnts;
	} else {
		ctx->pool = GEO_SAMPLING_POOL + cpu;
	}
}

static __always_inline u32 gen_geo_cnt(struct geo_sampling_ctx *ctx)
{
	uint32_t geo_value_idx = ctx->geo_sampling_idx;
	geo_value_idx = (geo_value_idx + 1) & GEO_SAMPLING_MASK;
	ctx->geo_sampling_idx = geo_value_idx;
	return (*ctx->pool)[geo_value_idx];
};

/**********NITRO SKETCH KERENL MODUEL IMPL***************/

struct countmin {
	u32 values[HASHFN_N][COLUMNS];
};

struct sketch_nitro_map {
	struct bpf_map map;
	struct countmin cm;
	struct geo_sampling_ctx __percpu *geo_ctx;
};

static int sketch_nitro_alloc_check(union bpf_attr *attr)
{
	if (attr->key_size != sizeof(raw_skp_key_type)) {
		pr_err("sk_nitro: invalid key size\n");
		return -EINVAL;
	}

	return 0;
}

static struct bpf_map *sketch_nitro_alloc(union bpf_attr *attr)
{
	int cpu, err;
	struct sketch_nitro_map *nitro;
	nitro = kmalloc(sizeof(*nitro), GFP_KERNEL);
	if (nitro == NULL)
		return ERR_PTR(-ENOMEM);
	memset(nitro, 0, sizeof(*nitro));

	/*init geo*/
	nitro->geo_ctx = alloc_percpu(struct geo_sampling_ctx);
	if (nitro->geo_ctx == NULL) {
		err = -ENOMEM;
		goto free_nitro;
	}

	for_each_possible_cpu(cpu) {
		init_geo_sampling_pool(per_cpu_ptr(nitro->geo_ctx, cpu), cpu);
	}

	return (struct bpf_map *)nitro;

free_geo_ctx:;
	free_percpu(nitro->geo_ctx);

free_nitro:;
	kfree(nitro);
	return ERR_PTR(err);
}

static void sketch_nitro_free(struct bpf_map *map)
{
	struct sketch_nitro_map *nitro = (struct sketch_nitro_map *)map;
	free_percpu(nitro->geo_ctx);
	kfree(nitro);
}

static inline void __nitrosketch_countmin_add(struct countmin *cm,
					      void *element, u64 len,
					      u32 row_to_update)
{
	for (int i = 0; i < HASHFN_N; i++) {
		u32 hash = crc32c(element, len, seeds[row_to_update]);
		u32 target_idx = hash & (COLUMNS - 1);
		__sync_fetch_and_add(&cm->values[row_to_update][target_idx], 1);
	}
}

static long sketch_nitro_update_elem(struct bpf_map *map, void *key,
				     void *value, u64 flag)
{
	/*for each rows:
	 * 1. generate geo ctx
	 * 2. selectively update row of skp
	 */
	struct sketch_nitro_map *nitro = (struct sketch_nitro_map *)map;
	int i;
	u32 row_to_update;
	geo_cnt_t next_geo_value;
	struct geo_sampling_ctx *geo_ctx;
	geo_ctx = this_cpu_ptr(nitro->geo_ctx);
	if (geo_ctx->cnt >= HASHFN_N) {
		/*skip this update*/
		geo_ctx->cnt -= HASHFN_N;
		return 0;
	}
	row_to_update = geo_ctx->cnt;
	for (i = 0; i < HASHFN_N; i++) {
		__nitrosketch_countmin_add(&nitro->cm, key,
					   sizeof(raw_skp_key_type),
					   row_to_update & (HASHFN_N - 1));

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
	pr_info("%s: module init\n", THIS_MODULE->name);
	return bpf_register_static_cmap(&sketch_nitro_ops, THIS_MODULE);
}

static void __exit sketch_lib_exp_exit(void)
{
	pr_info("%s: module exit\n", THIS_MODULE->name);
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
