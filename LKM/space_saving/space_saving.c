#include <linux/cpumask.h>
#include <linux/percpu.h>
#include <linux/random.h>
#include <linux/module.h>
#include <linux/bpf.h>
#include <linux/xxhash.h>

#ifdef SS_DEBUG
#include "../test_helpers.h"
#include <linux/proc_fs.h>
#endif

#ifdef SS_SIMD
/* This macro is required to include <immintrin.h> in the kernel */
#define _MM_MALLOC_H_INCLUDED
#include <immintrin.h>

#define _mm256_loadu_si256_optional(ptr)                                       \
	(u64)(ptr) & ((1 << 5) - 1) ? _mm256_loadu_si256((__m256i_u *)(ptr)) : \
				      (*(__m256i *)(ptr))
#endif

#define ss_log(level, fmt, ...) pr_##level("space_saving: " fmt, ##__VA_ARGS__)

typedef u16 ss_count_t;

#define SS_NUM_COUNTERS 8
#if SS_NUM_COUNTERS % 8 != 0
#error currently SS_NUM_COUNTERS must be a multiple of 8 for SIMD implementation to work
#endif

#define SS_KEY_SIZE 16
#if SS_KEY_SIZE % 4 != 0
#error currently SS_KEY_SIZE must be a multiple of 4 for SIMD implementation to work
#endif

#define SS_COUNT_SIZE sizeof(ss_count_t)
/* Currently SS_COUNT_SIZE must be 2 for SIMD implementation to work */

extern int register_btf_kfunc_id_set(enum bpf_prog_type prog_type,
				     const struct btf_kfunc_id_set *kset);

struct ss_table {
	u8 keys[SS_KEY_SIZE * SS_NUM_COUNTERS];
	ss_count_t counts[SS_NUM_COUNTERS];
	ss_count_t overestimates[SS_NUM_COUNTERS];
};

struct ss_table_bpf_map {
	struct bpf_map map;
	struct ss_table __percpu *tbl;
};

extern int bpf_register_static_cmap(struct bpf_map_ops *map,
				    struct module *owner);
extern void bpf_unregister_static_cmap(struct module *owner);
extern void bpf_map_area_free(void *area);
extern void *bpf_map_area_alloc(u64 size, int numa_node);

#ifdef SS_SIMD
static inline u32 __find_mask_u32_avx(const u32 *arr, u32 val)
{
	__m256i arr_vec = _mm256_loadu_si256_optional(arr),
		val_vec = _mm256_set1_epi32(val);
	__m256i cmp = _mm256_cmpeq_epi32(arr_vec, val_vec);
	u32 mask = _mm256_movemask_epi8(cmp);
	return mask;
}

static inline u32 __find_min_u16_sse(const u16 *arr, size_t len, u16 *min_val)
{
	u16 value, min_value = arr[0];
	u32 i, min_index = 0;
	__m128i arr_vec, res;

	for (i = 0; i < len; i += 8) {
		arr_vec = _mm_loadu_si128((__m128i_u *)(arr + i));
		res = _mm_minpos_epu16(arr_vec);
		value = _mm_extract_epi16(res, 0);
		if (value < min_value) {
			min_value = value;
			min_index = i + _mm_extract_epi16(res, 1);
		}
	}

	*min_val = min_value;
	return min_index;
}
#endif

static int ss_alloc_check(union bpf_attr *attr)
{
	int ret = 0;

	if (attr->max_entries != SS_NUM_COUNTERS) {
		ss_log(err, "invalid max_entries: %d\n", attr->max_entries);
		ret = -EINVAL;
		goto out;
	}

	if (attr->key_size != SS_KEY_SIZE) {
		ss_log(err, "invalid key_size: %d\n", attr->key_size);
		ret = -EINVAL;
		goto out;
	}

	if (attr->value_size != SS_COUNT_SIZE) {
		ss_log(err, "invalid value_size: %d\n", attr->value_size);
		ret = -EINVAL;
		goto out;
	}

out:
	return ret;
}

static struct bpf_map *ss_alloc(union bpf_attr *attr)
{
	struct ss_table_bpf_map *map;
	struct ss_table *tbl;
	int err;

	map = kvzalloc(sizeof(*map), GFP_USER | __GFP_NOWARN);
	if (map == NULL) {
		ss_log(err, "failed to allocate map\n");
		err = -ENOMEM;
		goto err;
	}

	tbl = alloc_percpu_gfp(typeof(*tbl),
			       GFP_USER | __GFP_NOWARN | __GFP_ZERO);
	if (tbl == NULL) {
		ss_log(err, "failed to allocate table\n");
		err = -ENOMEM;
		goto err_free_map;
	}
	map->tbl = tbl;

	return (struct bpf_map *)map;

err_free_map:
	kvfree(map);
err:
	return ERR_PTR(err);
}

static void ss_free(struct bpf_map *map)
{
	struct ss_table_bpf_map *ss_map = (struct ss_table_bpf_map *)map;
	struct ss_table *tbl;

	if (ss_map == NULL) {
		return;
	}

	tbl = ss_map->tbl;

	free_percpu(tbl);
	kvfree(ss_map);
}

static void *ss_lookup_elem(struct bpf_map *map, void *key)
{
	/* TODO: */
	return ERR_PTR(-ENOTSUPP);
}

static int ss_increment(struct ss_table *tbl, void *key)
{
	ss_count_t min_count = tbl->counts[0];
	u32 min_idx = 0, i, blk_idx;
	int ret = 0;

#ifdef SS_DEBUG
	ss_log(debug, "key hash = 0x%08x\n", xxh32(key, SS_KEY_SIZE, 0));
#endif

#ifdef SS_SIMD
	u32 mask;

	for (i = 0; i < SS_NUM_COUNTERS; i += 8) {
		mask = ~0;

		for (blk_idx = 0; blk_idx < SS_KEY_SIZE / 4; ++blk_idx) {
			mask &= __find_mask_u32_avx(
				(const u32 *)tbl->keys +
					blk_idx * SS_NUM_COUNTERS + i,
				((const u32 *)key)[blk_idx]);
			if (mask == 0) {
				goto replace_or_insert;
			}
		}

		i += __tzcnt_u32(mask) >> 2;
		ss_log(debug,
		       "found matching key (with SIMD) at %d, count = %d\n", i,
		       tbl->counts[i]);
		tbl->counts[i]++;
		goto out;
	}
#else
	for (i = 0; i < SS_NUM_COUNTERS; i++) {
		for (blk_idx = 0; blk_idx < SS_KEY_SIZE / 4; ++blk_idx) {
			if (((const u32 *)tbl->keys)[blk_idx * 8 + i] !=
			    ((const u32 *)key)[blk_idx]) {
				break;
			}
		}

		if (blk_idx == SS_KEY_SIZE / 4) {
			ss_log(debug, "found matching key at %d, count = %d\n",
			       i, tbl->counts[i]);
			tbl->counts[i]++;
			goto out;
		}
	}
#endif

	/* This is also responsible for inserting new keys when the table is not full,
     * since the counts are initialized to 0.
     */
#ifdef SS_SIMD
replace_or_insert:
	min_idx = __find_min_u16_sse(tbl->counts, SS_NUM_COUNTERS, &min_count);
#else
	for (i = 0; i < SS_NUM_COUNTERS; i++) {
		if (tbl->counts[i] < min_count) {
			min_count = tbl->counts[i];
			min_idx = i;
		}
	}
#endif

	ss_log(debug, "replacing (or inserting new) key at %d, count = %d\n",
	       min_idx, min_count);

	for (blk_idx = 0; blk_idx < SS_KEY_SIZE / 4; ++blk_idx) {
		((u32 *)tbl->keys)[blk_idx * SS_NUM_COUNTERS + min_idx] =
			((const u32 *)key)[blk_idx];
	}
	tbl->overestimates[min_idx] = min_count;
	tbl->counts[min_idx] = min_count + 1;
	ret = 0;

out:
	return ret;
}

long ss_update_elem(struct bpf_map *map, void *key, void *value, u64 flags)
{
	struct ss_table_bpf_map *ss_map = (struct ss_table_bpf_map *)map;
	struct ss_table *tbl;
	int ret = 0;

#ifdef SS_DEBUG
	if (ss_map == NULL) {
		ss_log(err, "invalid map; this should never happen\n");
		ret = -EINVAL;
		goto out;
	}
#endif

	tbl = this_cpu_ptr(ss_map->tbl);
	ret = ss_increment(tbl, key);

out:
	return ret;
}

__bpf_kfunc long bpf_ss_update_elem(struct bpf_map *map, void *key,
				    size_t key__sz, void *value,
				    size_t value__sz, u64 flags)
{
	return ss_update_elem(map, key, value, flags);
}
EXPORT_SYMBOL_GPL(bpf_ss_update_elem);

uint64_t ss_mem_usage(const struct bpf_map *map)
{
	return sizeof(struct ss_table_bpf_map) +
	       num_possible_cpus() * sizeof(struct ss_table);
}

static struct bpf_map_ops ss_ops = {
	.map_alloc_check = ss_alloc_check,
	.map_alloc = ss_alloc,
	.map_free = ss_free,
	.map_lookup_elem = ss_lookup_elem,
	.map_update_elem = ss_update_elem,
	.map_mem_usage = ss_mem_usage,
};

BTF_SET8_START(bpf_ss_kfunc_ids)
BTF_ID_FLAGS(func, bpf_ss_update_elem)
BTF_SET8_END(bpf_ss_kfunc_ids)

static const struct btf_kfunc_id_set bpf_ss_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_ss_kfunc_ids,
};

static int ss_initialize(void)
{
	int ret;

	if ((ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
					     &bpf_ss_kfunc_set)) < 0) {
		ss_log(err, "failed to register kfunc set: %d\n", ret);
		goto out;
	}

out:
	return ret;
}

static void ss_cleanup(void)
{
	// Nothing to do
}

#ifdef SS_DEBUG
static struct proc_dir_entry *ent;

struct pkt_5tuple {
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	uint8_t proto;
	uint8_t pad[3];
} __attribute__((packed));

static int __testing_alloc(struct inode *inode, struct file *filp)
{
	struct bpf_map *map;
	union bpf_attr attr;
	int ret = 0;

	ss_log(debug, "try module get\n");
	if (!try_module_get(THIS_MODULE)) {
		ret = -ENODEV;
		ss_log(err, "failed to take module\n");
		goto out;
	}

	/*testing alloc here*/
	ss_log(debug, "start testing alloc\n");

	attr.key_size = sizeof(struct pkt_5tuple);
	attr.value_size = sizeof(ss_count_t);
	attr.max_entries = SS_NUM_COUNTERS;

	if ((ret = ss_alloc_check(&attr))) {
		ss_log(err, "failed to check alloc: %d\n", ret);
		goto out_put_module;
	}

	map = ss_alloc(&attr);
	if (IS_ERR_OR_NULL(map)) {
		ret = PTR_ERR(map);
		ss_log(err, "failed to alloc map: %d\n", ret);
		goto out_put_module;
	}
	ss_log(debug, "testing alloc success\n");
	filp->private_data = (void *)map;

	goto out;

out_put_module:
	module_put(THIS_MODULE);
out:
	return ret;
}

static int __testing_release(struct inode *inode, struct file *file)
{
	struct bpf_map *map;

	ss_log(debug, "start testing free\n");
	/*testing free here*/
	map = (struct bpf_map *)file->private_data;
	ss_log(debug, "testing free\n");
	ss_free(map);
	ss_log(debug, "testing free success\n");
	module_put(THIS_MODULE);
	return 0;
}

static ssize_t __testing_operation(struct file *flip, char __user *ubuf,
				   size_t count, loff_t *ppos)
{
	/* testing data structure operation*/
	struct bpf_map *map;
	int ret = 0, i;

	ss_log(debug, "testing space saving operation\n");
	map = (struct bpf_map *)(flip->private_data);

	struct pkt_5tuple pkts[SS_NUM_COUNTERS + 8];
	ss_count_t dummy = 0;
	get_random_bytes(pkts, sizeof(pkts));

	for (i = 0; i < SS_NUM_COUNTERS; ++i) {
		ss_log(debug, "inserting %d\n", i);
		ret = ss_update_elem(map, &pkts[i], &dummy, BPF_ANY);
		lkm_assert_eq(0, ret, "ss_update_elem should succeed");
	}

	for (i = 0; i < ARRAY_SIZE(pkts); ++i) {
		ss_log(debug, "updating %d\n", i);
		ret = ss_update_elem(map, &pkts[i], &dummy, BPF_ANY);
		lkm_assert_eq(0, ret, "ss_update_elem should succeed");
	}

	ss_log(info, "testing space saving success\n");
	return 0; /*always not insert the mod*/

lkm_test_error:
	ss_log(err, "testing space saving failed with res %d\n", ret);
	return 0;
}

static struct proc_ops testing_ops = {
	.proc_open = __testing_alloc,
	.proc_read = __testing_operation,
	.proc_release = __testing_release,
};

static int ss_proc_init(void)
{
	ent = proc_create("testing_space_saving", 0440, NULL, &testing_ops);
	if (IS_ERR_OR_NULL(ent))
		return -2;
	return 0;
}

static void ss_proc_cleanup(void)
{
	proc_remove(ent);
}
#endif

static int __init ss_init(void)
{
	int ret = 0;

	if ((ret = ss_initialize()) != 0) {
		ss_log(err, "failed to initialize\n");
		goto out;
	}

	if ((ret = bpf_register_static_cmap(&ss_ops, THIS_MODULE)) != 0) {
		ss_log(err, "failed to register static cmap\n");
		goto out;
	}

#ifdef SS_DEBUG
	if ((ret = ss_proc_init()) != 0) {
		ss_log(err, "failed to initialize proc\n");
		goto out;
	}
#endif

	ss_log(info, "initialized\n");

out:
	return ret;
}

static void __exit ss_exit(void)
{
#ifdef SS_DEBUG
	ss_proc_cleanup();
#endif
	bpf_unregister_static_cmap(THIS_MODULE);
	ss_cleanup();

	ss_log(info, "exiting\n");
}

/* Register module functions */
module_init(ss_init);
module_exit(ss_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yang Hanlin");
MODULE_DESCRIPTION("Space-Saving algorithm LKM implementation");
MODULE_VERSION("0.0.1");
