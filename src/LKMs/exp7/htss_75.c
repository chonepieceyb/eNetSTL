#include "linux/gfp_types.h"
#include <linux/init.h> 
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include "crc.h"

extern int bpf_register_static_cmap(struct bpf_map_ops *map, struct module *onwer);
extern void bpf_unregister_static_cmap(struct module *onwer);
extern void bpf_map_area_free(void *area);
extern void *bpf_map_area_alloc(u64 size, int numa_node);

/* static vars */
#define MAX_ENTRY 2048
#define HASH_SEED_1 0xdeadbeef
#define HASH_SEED_2 0xaaaabbbb
#define MEMBER_NO_MATCH 0
#define MEMBER_MAX_PUSHES 8

/* datastruct params */
#define NUM_ENTRIES 1024
#define NUM_BUCKETS 128
#define SIZE_BUCKET_T 32
#define BUCKET_MASK 127
#define MEMBER_BUCKET_ENTRIES 16

#define TEST_RANGE 136

/* bitwise operation */
static inline __u32
ctz32(__u32 v)
{
	return (unsigned int)__builtin_ctz(v);
}

typedef __u16 sig_t;
typedef __u16 set_t;
struct member_ht_bucket {
	sig_t sigs[MEMBER_BUCKET_ENTRIES];
	set_t sets[MEMBER_BUCKET_ENTRIES];
};
struct htss_memory {
	struct member_ht_bucket buckets[NUM_BUCKETS];
	rwlock_t rw_lock;
};

struct static_htss_map {
	struct bpf_map map;
	struct htss_memory *table;
};

int htss_alloc_check(union bpf_attr *attr) {
	if (attr->max_entries > MAX_ENTRY) {
		return -EINVAL;
	}
	return 0;
}

static struct bpf_map *htss_alloc(union bpf_attr *attr)
{
	//demo alloc we just alloc char[hello world]
	struct static_htss_map *htss_map;
	void *res_ptr; 
	int cpu;

	htss_map = bpf_map_area_alloc(sizeof(struct static_htss_map), NUMA_NO_NODE);
	if (htss_map == NULL) {
		return ERR_PTR(-ENOMEM);
	}

	htss_map->table = kmalloc(attr->key_size * NUM_BUCKETS * MEMBER_BUCKET_ENTRIES, GFP_ATOMIC);
	if (htss_map->table == NULL) {
		res_ptr = ERR_PTR(-ENOMEM);
		goto free_tmap;
	}
	struct htss_memory* __htss = htss_map->table;
	memset(__htss, 0, sizeof(struct htss_memory));
	rwlock_init (&__htss->rw_lock);
	return (struct bpf_map*)htss_map;
free_tmap:
	return res_ptr;
}

static void htss_free(struct bpf_map *map) {
	struct static_htss_map *htss_map;
	if (map == NULL) {
		return;
	}
	htss_map = container_of(map, struct static_htss_map, map);

	kfree(htss_map->table);
	bpf_map_area_free(htss_map);
	return;
}

/* htss helper function */
void
get_buckets_index(void *key, __u32 key_len, __u32 *prim_bkt, __u32 *sec_bkt, sig_t *sig)
{
	/* 和vbf一样，计算两个hash值，其中 h1 = hash(key) h2 = hash(hash(key)) */
	__u32 first_hash = crc32c(key, key_len, HASH_SEED_1);
	__u32 sec_hash = crc32c(&first_hash, sizeof(__u32), HASH_SEED_2);
	*sig = first_hash;
	*prim_bkt = sec_hash & BUCKET_MASK;
	*sec_bkt =  (*prim_bkt ^ *sig) & BUCKET_MASK;

}

int
try_insert(struct member_ht_bucket *buckets, __u32 prim, __u32 sec,
		sig_t sig, set_t set_id)
{
	int i;
	/* If not full then insert into one slot */
	for (i = 0; i < MEMBER_BUCKET_ENTRIES; i++) {
		if (buckets[prim].sets[i] == MEMBER_NO_MATCH) {
			buckets[prim].sigs[i] = sig;
			buckets[prim].sets[i] = set_id;
			// pr_debug("insert %d at prim bucket:%u, set:%u\n", set_id, prim, i);
			return 0;
		}
	}
	/* If prim failed, we need to access second bucket */
	for (i = 0; i < MEMBER_BUCKET_ENTRIES; i++) {
		if (buckets[sec].sets[i] == MEMBER_NO_MATCH) {
			buckets[sec].sigs[i] = sig;
			buckets[sec].sets[i] = set_id;
			// pr_debug("insert %d at sec bucket:%u, set:%u\n", set_id, prim, i);
			return 0;
		}
	}
	return -1;
}

int
make_space_bucket(struct member_ht_bucket *buckets, __u32 bkt_idx,
			unsigned int *nr_pushes)
{
	unsigned int i, j;
	int ret;
	__u32 next_bucket_idx;
	struct member_ht_bucket *next_bkt[MEMBER_BUCKET_ENTRIES];
	struct member_ht_bucket *bkt = &buckets[bkt_idx];
	/* MSB is set to indicate if an entry has been already pushed */
	set_t flag_mask = 1U << (sizeof(set_t) * 8 - 1);

	/*
	 * Push existing item (search for bucket with space in
	 * alternative locations) to its alternative location
	 */
	for (i = 0; i < MEMBER_BUCKET_ENTRIES; i++) {
		/* Search for space in alternative locations */
		next_bucket_idx = (bkt->sigs[i] ^ bkt_idx) & BUCKET_MASK;
		next_bkt[i] = &buckets[next_bucket_idx];
		for (j = 0; j < MEMBER_BUCKET_ENTRIES; j++) {
			if (next_bkt[i]->sets[j] == MEMBER_NO_MATCH)
				break;
		}

		if (j != MEMBER_BUCKET_ENTRIES)
			break;
	}

	/* Alternative location has spare room (end of recursive function) */
	if (i != MEMBER_BUCKET_ENTRIES) {
		next_bkt[i]->sigs[j] = bkt->sigs[i];
		next_bkt[i]->sets[j] = bkt->sets[i];
		return i;
	}

	/* Pick entry that has not been pushed yet */
	for (i = 0; i < MEMBER_BUCKET_ENTRIES; i++)
		if ((bkt->sets[i] & flag_mask) == 0)
			break;

	/* All entries have been pushed, so entry cannot be added */
	if (i == MEMBER_BUCKET_ENTRIES) {
		return -ENOSPC;
	}
	if (++(*nr_pushes) > MEMBER_MAX_PUSHES){
		return -ENOSPC;
	}
	next_bucket_idx = (bkt->sigs[i] ^ bkt_idx) & BUCKET_MASK;
	/* Set flag to indicate that this entry is going to be pushed */
	bkt->sets[i] |= flag_mask;

	/* Need room in alternative bucket to insert the pushed entry */
	ret = make_space_bucket(buckets, next_bucket_idx, nr_pushes);
	/*
	 * After recursive function.
	 * Clear flags and insert the pushed entry
	 * in its alternative location if successful,
	 * or return error
	 */
	bkt->sets[i] &= ~flag_mask;
	if (ret >= 0) {
		next_bkt[i]->sigs[ret] = bkt->sigs[i];
		next_bkt[i]->sets[ret] = bkt->sets[i];
		return i;
	} else
		return ret;
}

set_t* search_bucket_single_avx(__u32 bucket_id, sig_t tmp_sig, struct member_ht_bucket *buckets)
{
	/**
	 * @brief 将16bit的tmp_sig复制16份，扩展到256位，与bucket对应位置的签名对比（一个simd实现了比较16次哈希）
	 * _mm256_movemask_epi8 
	 * _mm256_cmpeq_epi16 按16位的int依次对比，每一组，相等时对应16bit返回0xFFFF，不相等时返回0
	 * _mm256_load_si256 从指定地址的内存加载256位数据
	 * _mm256_set1_epi16 将传入的16bit的int，复制16份，扩展到256位
	 */
	__u32 hitmask = _mm256_movemask_epi8((__m256i)_mm256_cmpeq_epi16(
		_mm256_load_si256((__m256i const *)buckets[bucket_id].sigs),
		_mm256_set1_epi16(tmp_sig)));
	while (hitmask) {
		__u32 hit_idx = ctz32(hitmask) >> 1;
		if (buckets[bucket_id].sets[hit_idx] != MEMBER_NO_MATCH) {
			return &buckets[bucket_id].sets[hit_idx];
		}
		hitmask &= ~(3U << ((hit_idx) << 1));
	}
	return NULL;
}

static void* htss_lookup_elem(struct bpf_map *map, void *key) 
{
	struct static_htss_map *htss_map = container_of(map, struct static_htss_map, map);
	struct htss_memory *__htss = htss_map->table;
	struct member_ht_bucket *buckets = __htss->buckets;

	__u32 prim_bucket, sec_bucket;
	sig_t tmp_sig;
	// add read lock
	read_lock(&__htss->rw_lock);
	get_buckets_index(key, map->key_size, &prim_bucket, &sec_bucket, &tmp_sig);

	set_t *search_res = search_bucket_single_avx(prim_bucket, tmp_sig, buckets);
	// if result not present in first bucket, search second bucket
	if (search_res == NULL) {
		search_res = search_bucket_single_avx(sec_bucket, tmp_sig, buckets);
	}

	read_unlock(&__htss->rw_lock);
	return search_res;
}

static long htss_update_elem(struct bpf_map *map, void *key, void *value, u64 flag) {
	struct static_htss_map *htss_map = container_of(map, struct static_htss_map, map);
	struct htss_memory *__htss = htss_map->table;
	struct member_ht_bucket *buckets = __htss->buckets;
	
	long ret;
	unsigned int nr_pushes = 0;
	__u32 prim_bucket = 0;
	__u32 sec_bucket = 0;
	sig_t tmp_sig = 0;
	set_t flag_mask = 1U << (sizeof(set_t) * 8 - 1);
	__u32 set_id = *(__u32 *)value;

	if (set_id == MEMBER_NO_MATCH || (set_id & flag_mask) != 0) {
		return -1;
	}
	// add writer lock
	write_lock(&__htss->rw_lock);
	get_buckets_index(key, map->key_size, &prim_bucket, &sec_bucket, &tmp_sig);
	ret = try_insert(buckets, prim_bucket, sec_bucket, tmp_sig, set_id);
	if (ret != -1)
		goto unlock;

	/* Random pick prim or sec for recursive displacement */
	__u32 select_bucket = (tmp_sig && 1U) ? prim_bucket : sec_bucket;

	ret = make_space_bucket(buckets, select_bucket, &nr_pushes);
	if (ret >= 0) {
		buckets[select_bucket].sigs[ret] = tmp_sig;
		buckets[select_bucket].sets[ret] = set_id;
		ret = 1;
		goto unlock;
	}
unlock:
	write_unlock(&__htss->rw_lock);
	return ret;
}

static u64 htss_mem_usage(const struct bpf_map *map) 
{
	return sizeof(struct htss_memory) * num_possible_cpus();
}


static struct bpf_map_ops cmap_ops = {
	.map_alloc_check = htss_alloc_check,
	.map_alloc = htss_alloc,
	.map_free = htss_free,
	.map_lookup_elem = htss_lookup_elem,
	.map_update_elem = htss_update_elem,
	.map_mem_usage = htss_mem_usage
};

static int __init static_cmap_htss_init(void) {
	pr_info("register static htss_cmaps");
	return bpf_register_static_cmap(&cmap_ops, THIS_MODULE);
}

static void __exit static_cmap_htss_exit(void) {
	pr_info("unregister static htss_cmaps");
	bpf_unregister_static_cmap(THIS_MODULE);
}

/* Register module functions */
module_init(static_cmap_htss_init);
module_exit(static_cmap_htss_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("LunqiZhao");
MODULE_DESCRIPTION("DPDK HTSS implementation.");
MODULE_VERSION("0.01");