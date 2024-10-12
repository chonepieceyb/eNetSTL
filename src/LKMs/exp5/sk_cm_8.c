#include <linux/module.h>
#include "linux/errno.h"
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/cpumask.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/random.h>
#include <linux/xxhash.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/bpf_mem_alloc.h>

#include "xxhash_simd.h"
#include "crc.h"

#ifdef COUNTMIN_DEBUG
#include "../test_helpers.h"
#include <linux/proc_fs.h>
#endif

#define _CS_ROWS 8
#define _CS_COLUMNS 64
#define _NM_LAYERS 32
#define HASHFN_N _CS_ROWS
#define COLUMNS _CS_COLUMNS
#define USE_SIMD 1
#define USE_XXHASH 1 /*switch between fasthash and xx hash*/

#define COUNTMIN_KEY_SIZE 16

#if HASHFN_N <= 2
#define USE_CRC
#elif HASHFN_N > 8
#error Unsupported number of hash functions
#endif

#define countmin_log(level, fmt, ...)                                 \
	pr_##level("%s: " fmt " (%s @ line %d)\n", THIS_MODULE->name, \
		   ##__VA_ARGS__, __func__, __LINE__)

typedef u16 sk_cm_count_t;

struct countmin {
	__u32 values[HASHFN_N][COLUMNS];
};

struct countmin_map {
	struct bpf_map map;
	struct countmin __percpu *table;
};

extern int bpf_register_static_cmap(struct bpf_map_ops *map,
				    struct module *owner);
extern void bpf_unregister_static_cmap(struct module *owner);
extern void bpf_map_area_free(void *area);
extern void *bpf_map_area_alloc(u64 size, int numa_node);

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

static int countmin_alloc_check(union bpf_attr *attr)
{
	int ret = 0;

	countmin_log(debug, "checking allocation: attr = %p", attr);

	if (attr->key_size != COUNTMIN_KEY_SIZE) {
		countmin_log(err, "invalid key_size: %d", attr->key_size);
		ret = -EINVAL;
		goto out;
	}

out:
	return ret;
}

static struct bpf_map *countmin_alloc(union bpf_attr *attr)
{
	struct countmin_map *map;
	struct countmin *table, *tbl;
	int err, cpu;

	countmin_log(debug, "allocating map: attr = %p, size = %lu", attr,
		     sizeof(*map));
	map = kvzalloc(sizeof(*map), GFP_USER | __GFP_NOWARN);
	if (map == NULL) {
		countmin_log(err, "failed to allocate map");
		err = -ENOMEM;
		goto err;
	}

	countmin_log(debug, "allocating table: size = %lu", sizeof(*table));
	table = alloc_percpu_gfp(typeof(*table),
				 GFP_USER | __GFP_NOWARN | __GFP_ZERO);
	if (table == NULL) {
		countmin_log(err, "failed to allocate table");
		err = -ENOMEM;
		goto err_free_map;
	}
	for_each_possible_cpu(cpu) {
		tbl = per_cpu_ptr(table, cpu);
		countmin_log(debug, "initializing table for CPU %d: tbl = %p",
			     cpu, tbl);
		memset(tbl, 0, sizeof(*tbl));
	}
	map->table = table;

	return (struct bpf_map *)map;

err_free_map:
	kvfree(map);
err:
	return ERR_PTR(err);
}

static void countmin_free(struct bpf_map *map)
{
	struct countmin *table;

	if (map == NULL) {
		countmin_log(debug, "map is NULL; ignoring");
		return;
	}

	table = ((struct countmin_map *)map)->table;
	free_percpu(table);

	countmin_log(debug, "freeing map: map = %p", map);
	kvfree(map);
}

static void *countmin_lookup_elem(struct bpf_map *map, void *key)
{
	/* TODO: */
	return ERR_PTR(-ENOTSUPP);
}

static int countmin_add(struct countmin *table, void *key)
{
	int ret = 0;

#ifndef USE_CRC
	__m256i seeds_vec = _mm256_loadu_si256((const __m256i_u *)seeds);
	__m256i hashes_vec = xxh32_avx2_pkt5(key, &seeds_vec);
	u32 *hashes = (u32 *)&hashes_vec;
#endif /* USE_CRC */

	for (int i = 0; i < HASHFN_N; ++i) {
#ifdef USE_CRC
		u32 hash = crc32c(key, COUNTMIN_KEY_SIZE, seeds[i]);
#else /* USE_CRC */
		u32 hash = hashes[i];
#endif /* USE_CRC */
		table->values[i][hash % COLUMNS]++;
	}

	return ret;
}

long countmin_update_elem(struct bpf_map *map, void *key, void *value,
			  u64 flags)
{
	struct countmin *table;
	int ret = 0;

	if (map == NULL) {
		ret = -EINVAL;
		goto out;
	}

	table = this_cpu_ptr(((struct countmin_map *)map)->table);
	ret = countmin_add(table, key);

out:
	return ret;
}

uint64_t countmin_mem_usage(const struct bpf_map *map)
{
	return sizeof(struct countmin_map) +
	       num_possible_cpus() * (sizeof(struct countmin));
}

static struct bpf_map_ops countmin_ops = {
	.map_alloc_check = countmin_alloc_check,
	.map_alloc = countmin_alloc,
	.map_free = countmin_free,
	.map_lookup_elem = countmin_lookup_elem,
	.map_update_elem = countmin_update_elem,
	.map_mem_usage = countmin_mem_usage,
};

static int countmin_initialize(void)
{
	return 0;
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

	countmin_log(debug, "try module get");
	if (!try_module_get(THIS_MODULE)) {
		ret = -ENODEV;
		countmin_log(err, "failed to take module");
		goto out;
	}

	/*testing alloc here*/
	countmin_log(debug, "start testing alloc");

	attr.key_size = sizeof(struct pkt_5tuple);
	attr.value_size = sizeof(countmin_count_t);
	attr.max_entries = SS_CAPACITY;

	if ((ret = countmin_alloc_check(&attr))) {
		countmin_log(err, "failed to check alloc: %d", ret);
		goto out_put_module;
	}

	map = countmin_alloc(&attr);
	if (IS_ERR_OR_NULL(map)) {
		ret = PTR_ERR(map);
		countmin_log(err, "failed to alloc map: %d", ret);
		goto out_put_module;
	}
	countmin_log(debug, "testing alloc success");
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

	countmin_log(debug, "start testing free");
	/*testing free here*/
	map = (struct bpf_map *)file->private_data;
	countmin_log(debug, "testing free");
	countmin_free(map);
	countmin_log(debug, "testing free success");
	module_put(THIS_MODULE);
	return 0;
}

static ssize_t __testing_operation(struct file *flip, char __user *ubuf,
				   size_t count, loff_t *ppos)
{
	/* testing data structure operation*/
	struct bpf_map *map;
	int ret = 0, i;

	countmin_log(debug, "testing count-min operation");
	map = (struct bpf_map *)(flip->private_data);

	struct pkt_5tuple pkts[SS_CAPACITY + 8];
	countmin_count_t dummy = 0;
	get_random_bytes(pkts, sizeof(pkts));

	for (i = 0; i < SS_CAPACITY; ++i) {
		countmin_log(debug, "inserting %d", i);
		ret = countmin_update_elem(map, &pkts[i], &dummy, BPF_ANY);
		lkm_assert_eq(0, ret, "countmin_update_elem should succeed");
	}

	for (i = 0; i < ARRAY_SIZE(pkts); ++i) {
		countmin_log(debug, "updating %d", i);
		ret = countmin_update_elem(map, &pkts[i], &dummy, BPF_ANY);
		lkm_assert_eq(0, ret, "countmin_update_elem should succeed");
	}

	countmin_log(info, "testing count-min success");
	return 0; /*always not insert the mod*/

lkm_test_error:
	countmin_log(err, "testing count-min failed with res %d", ret);
	return 0;
}

static struct proc_ops testing_ops = {
	.proc_open = __testing_alloc,
	.proc_read = __testing_operation,
	.proc_release = __testing_release,
};

static int countmin_proc_init(void)
{
	ent = proc_create("testing_sk_cm", 0440, NULL, &testing_ops);
	if (IS_ERR_OR_NULL(ent))
		return -2;
	return 0;
}

static void countmin_proc_cleanup(void)
{
	proc_remove(ent);
}
#endif

static int __init countmin_init(void)
{
	int ret = 0;

	if ((ret = countmin_initialize()) != 0) {
		countmin_log(err, "failed to initialize");
		goto out;
	}

	if ((ret = bpf_register_static_cmap(&countmin_ops, THIS_MODULE)) != 0) {
		countmin_log(err, "failed to register static cmap");
		goto out;
	}

#ifndef USE_CRC
	xxh_init();
#endif

#ifdef COUNTMIN_DEBUG
	if ((ret = countmin_proc_init()) != 0) {
		countmin_log(err, "failed to initialize proc");
		goto out;
	}
#endif

	countmin_log(info, "initialized");

out:
	return ret;
}

static void __exit countmin_exit(void)
{
#ifdef COUNTMIN_DEBUG
	countmin_proc_cleanup();
#endif
	bpf_unregister_static_cmap(THIS_MODULE);

	countmin_log(info, "exiting");
}

/* Register module functions */
module_init(countmin_init);
module_exit(countmin_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chonepieceyb, Yang Hanlin");
MODULE_DESCRIPTION("Count-min sketch LKM implementation");
MODULE_VERSION("0.0.1");
