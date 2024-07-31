#include <linux/prandom.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/bpf.h>
#include <linux/types.h>

#define USE_SIMD_HASH 1

#include "fasthash.h"
#if defined(USE_SIMD_HASH) && USE_SIMD_HASH == 1
#include "fasthash_simd.h"
#include "crc.h"
#endif

extern int bpf_register_static_cmap(struct bpf_map_ops *map,
				    struct module *onwer);
extern void bpf_unregister_static_cmap(struct module *onwer);
extern void bpf_map_area_free(void *area);
extern void *bpf_map_area_alloc(__u64 size, int numa_node);

static __u32 seeds[] = {
	0xec5853,  0xec5859,  0xec5861,	 0xec587f,  0xec58a7,  0xec58b3,
	0xec58c7,  0xec58d1,  0xec58531, 0xec58592, 0xec58613, 0xec587f4,
	0xec58a75, 0xec58b36, 0xec58c77, 0xec58d18, 0xec58539, 0xec58510,
	0xec58611, 0xec58712, 0xec58a13, 0xec58b14, 0xec58c15, 0xec58d16,
	0xec58521, 0xec58522, 0xec58623, 0xec58724, 0xec58a25, 0xec58b26,
	0xec58c27, 0xec58d28, 0xec58541, 0xec58542, 0xec58643, 0xec58744,
	0xec58a45, 0xec58b46, 0xec58c47, 0xec58d48, 0xec58551, 0xec58552,
	0xec58653, 0xec58754, 0xec58a55, 0xec58b56, 0xec58c57, 0xec58d58,
	0xec58561, 0xec58563, 0xec58663, 0xec58764, 0xec58a65, 0xec58b66,
	0xec58c67, 0xec58d68, 0xec58571, 0xec58572, 0xec58673, 0xec58774,
	0xec58a75, 0xec58b76, 0xec58c77, 0xec58d78,
};

#define SKETCH_DEPTH 8
// 256 will cause no memmory error
#define SKETCH_WIDTH 128
#define SKETCH_KEY_SIZE sizeof(sketch_key)
#define BLOOMSIZE 32

/* definition of the packet 5 tuple */
struct pkt_5tuple {
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	uint8_t proto;
} __attribute__((packed));

struct pkt_5tuple_with_pad {
	struct pkt_5tuple pkt;
	__u8 pad[3];
} __attribute__((packed));
typedef struct pkt_5tuple_with_pad sketch_key;

struct sketch {
	__u32 flag;
	__u32 bloomMax;
	__u32 bloomMin;
	__u32 bloomCounts[BLOOMSIZE];
	//Heavy Keeper部分 20240722
	__u32 keys[SKETCH_WIDTH * SKETCH_DEPTH];
	sketch_key flows[SKETCH_WIDTH * SKETCH_DEPTH];
};

struct static_heavy_keeper_map {
	struct bpf_map map;
	struct sketch __percpu *tbl;
};

int heavy_keeper_alloc_check(union bpf_attr *attr)
{
	return 0;
}

static struct bpf_map *heavy_keeper_alloc(union bpf_attr *attr)
{
	//demo alloc we just alloc char[hello world]
	struct static_heavy_keeper_map *hk_map;
	void *res_ptr;
	int cpu;
	hk_map = bpf_map_area_alloc(sizeof(struct static_heavy_keeper_map),
				    NUMA_NO_NODE);
	if (hk_map == NULL) {
		return ERR_PTR(-ENOMEM);
	}
	hk_map->tbl = __alloc_percpu_gfp(sizeof(struct sketch),
					 __alignof__(u64),
					 GFP_USER | __GFP_NOWARN);
	if (hk_map->tbl == NULL) {
		res_ptr = ERR_PTR(-ENOMEM);
		goto free_tmap;
	}
	for_each_possible_cpu(cpu) {
		struct sketch *tbl;
		tbl = per_cpu_ptr(hk_map->tbl, cpu);
		memset(tbl, 0, sizeof(struct sketch));
	}
	return (struct bpf_map *)hk_map;
free_tmap:
	return res_ptr;
}

static void heavy_keeper_free(struct bpf_map *map)
{
	struct static_heavy_keeper_map *hh_map;
	if (map == NULL) {
		return;
	}
	hh_map = container_of(map, struct static_heavy_keeper_map, map);

	free_percpu(hh_map->tbl);
	bpf_map_area_free(hh_map);
	return;
}

//实现指数下降的概率
static inline int prob_action(u32 count)
{ //返回1 代表成功
	//随机采样
	u32 random_number = get_random_u32() % 100000;
	if (count < 11) {
		if (random_number < 96336 - 5312 * count)
			return 1;
	} else if (count < 21) {
		if (random_number < 69284 - 2463 * count)
			return 1;
	} else if (count < 31) {
		if (random_number < 43533 - 1142 * count)
			return 1;
	} else if (count < 41) {
		if (random_number < 25472 - 529 * count)
			return 1;
	} else if (count < 51) {
		if (random_number < 14261 - 245 * count)
			return 1;
	} else if (count < 61) {
		if (random_number < 7748 - 114 * count)
			return 1;
	} else if (count < 71) {
		if (random_number < 4119 - 53 * count)
			return 1;
	} else if (count < 81) {
		if (random_number < 2154 - 24 * count)
			return 1;
	} else if (count < 91) {
		if (random_number < 1112 - 11 * count)
			return 1;
	} else if (count < 101) {
		if (random_number < 568 - 5 * count)
			return 1;
	} else {
		if (random_number < 1)
			return 1;
	}

	return 0;
}

static inline int packet_memcmp(const void *s1, const void *s2, size_t n)
{
	const uint8_t *p1 = s1, *p2 = s2;
	int ret = 0;
	while (n--) {
		if ((ret = *p1++ - *p2++) != 0)
			break;
	}
	return ret;
}

static inline int flow_memcmp(const sketch_key *key1, const sketch_key *key2)
{
	return packet_memcmp(key1, key2, SKETCH_KEY_SIZE);
}

static void *heavy_keeper_lookup_elem(struct bpf_map *map, void *key)
{
	return NULL;
}

static long heavy_keeper_update_elem(struct bpf_map *map, void *key,
				     void *value, u64 flag)
{
	struct static_heavy_keeper_map *hh_map =
		container_of(map, struct static_heavy_keeper_map, map);
	struct sketch *tbl = this_cpu_ptr(hh_map->tbl);

#if defined(USE_SIMD_HASH) && USE_SIMD_HASH == 1
	__m256i seeds_vec = _mm256_loadu_si256((const __m256i_u *)seeds);
	__m256i hashes_vec = _fasthash64_avx2_pkt5(key, &seeds_vec);
	u32 *hashes = (u32 *)&hashes_vec;
#endif

	for (int i = 0; i < SKETCH_DEPTH; ++i) {
#if defined(USE_SIMD_HASH) && USE_SIMD_HASH == 1
#if SKETCH_DEPTH == 2
		u32 hash = crc32c(key, SKETCH_KEY_SIZE, seeds[i]);
#elif SKETCH_DEPTH == 8
		u32 hash = hashes[i];
#else
#error "Unsupported SKETCH_DEPTH"
#endif
#else
		u32 hash = fasthash32(key, SKETCH_KEY_SIZE, seeds[i]);
#endif
		int index = i * SKETCH_WIDTH + hash % SKETCH_WIDTH;
		if (tbl->keys[index] == 0) {
			tbl->flows[index] = *((sketch_key *)key);
			tbl->keys[index] = 1;
			continue;
		}
		if (flow_memcmp(tbl->flows + index, key) == 0) {
			//是当前包对应流
			pr_debug(
				"found matching key at %u array, %u bucket, count = %u ,src_ip=0x%08x",
				i, hash % SKETCH_WIDTH, tbl->keys[index],
				tbl->flows[index].pkt.src_ip);
			tbl->keys[index]++;
		} else {
			pr_debug(
				"not the matching key at %u array, %u bucket, count = %u ,src_ip=0x%08x ",
				i, hash % SKETCH_WIDTH, tbl->keys[index],
				tbl->flows[index].pkt.src_ip);
			if (tbl->keys[index] > 0 &&
			    prob_action(tbl->keys[index]) == 1)
				tbl->keys[index]--;
			if (tbl->keys[index] == 0) {
				tbl->flows[index] = *((sketch_key *)key);
				tbl->keys[index] = 1;
			}
		}
		// 对哈希结果取模映射到数组的某个位置，并增加计数值
	}
	return 0;
}

static u64 heavy_keeper_mem_usage(const struct bpf_map *map)
{
	return sizeof(struct sketch) * num_possible_cpus();
}

static struct bpf_map_ops cmap_ops = {
	.map_alloc_check = heavy_keeper_alloc_check,
	.map_alloc = heavy_keeper_alloc,
	.map_free = heavy_keeper_free,
	.map_lookup_elem = heavy_keeper_lookup_elem,
	.map_update_elem = heavy_keeper_update_elem,
	.map_mem_usage = heavy_keeper_mem_usage
};

static int __init static_cmap_heavy_keeper_init(void)
{
	pr_info("register static heavy_keeper_scmaps");
	return bpf_register_static_cmap(&cmap_ops, THIS_MODULE);
}

static void __exit static_cmap_heavy_keeper_exit(void)
{
	pr_info("unregister static heavy_keeper_scmaps");
	bpf_unregister_static_cmap(THIS_MODULE);
}

/* Register module functions */
module_init(static_cmap_heavy_keeper_init);
module_exit(static_cmap_heavy_keeper_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("LunqiZhao");
MODULE_DESCRIPTION("heavy_keeper implementation.");
MODULE_VERSION("0.01");
