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

#ifdef SS_DEBUG
#include "../test_helpers.h"
#include <linux/proc_fs.h>
#endif

#define ss_log(level, fmt, ...)                                   \
	pr_##level("space_saving_list: " fmt " (%s @ line %d)\n", \
		   ##__VA_ARGS__, __func__, __LINE__)

typedef u16 ss_count_t;

// default is 100
#define SS_CAPACITY 100
#define SS_KEY_SIZE 16
#define SS_COUNT_SIZE sizeof(ss_count_t)
#define SS_HASH_BITS 8
#define SS_HASH_SEED 0xdeadbeef

struct ss_bucket;

struct ss_element {
	struct list_head list;
	struct hlist_node hlist;
	struct ss_bucket *parent;

	u8 key[SS_KEY_SIZE];
};

struct ss_bucket {
	struct list_head list;
	struct list_head children;

	ss_count_t value;
};

struct ss_table {
	struct bpf_mem_alloc bucket_mem_alloc;
	struct bpf_mem_alloc element_mem_alloc;

	DECLARE_HASHTABLE(elements, SS_HASH_BITS);
	struct list_head buckets;
	size_t size;
};

struct ss_table_bpf_map {
	struct bpf_map map;
	struct ss_table __percpu *table;
};

extern int bpf_register_static_cmap(struct bpf_map_ops *map,
				    struct module *owner);
extern void bpf_unregister_static_cmap(struct module *owner);
extern void bpf_map_area_free(void *area);
extern void *bpf_map_area_alloc(u64 size, int numa_node);

static int ss_alloc_check(union bpf_attr *attr)
{
	int ret = 0;

	ss_log(debug, "checking allocation: attr = %p", attr);

	if (attr->max_entries != SS_CAPACITY) {
		ss_log(err, "invalid max_entries: %d", attr->max_entries);
		ret = -EINVAL;
		goto out;
	}

	if (attr->key_size != SS_KEY_SIZE) {
		ss_log(err, "invalid key_size: %d", attr->key_size);
		ret = -EINVAL;
		goto out;
	}

	if (attr->value_size != SS_COUNT_SIZE) {
		ss_log(err, "invalid value_size: %d", attr->value_size);
		ret = -EINVAL;
		goto out;
	}

out:
	return ret;
}

static inline struct ss_element *__ss_element_alloc(struct ss_table *table)
{
	struct ss_element *element;

	ss_log(debug, "allocating element: table = %p", table);
	element = bpf_mem_cache_alloc(&table->element_mem_alloc);
	if (element == NULL) {
		goto out;
	}

	ss_log(debug, "allocated element = %p; initializing", element);
	INIT_LIST_HEAD(&element->list);
	INIT_HLIST_NODE(&element->hlist);

out:
	return element;
}

static inline struct ss_bucket *__ss_bucket_alloc(struct ss_table *table)
{
	struct ss_bucket *bucket;

	ss_log(debug, "allocating bucket: table = %p", table);
	bucket = bpf_mem_cache_alloc(&table->bucket_mem_alloc);
	if (bucket == NULL) {
		goto out;
	}

	ss_log(debug, "allocated bucket = %p; initializing", bucket);
	INIT_LIST_HEAD(&bucket->list);
	INIT_LIST_HEAD(&bucket->children);

out:
	return bucket;
}

static struct bpf_map *ss_alloc(union bpf_attr *attr)
{
	struct ss_table_bpf_map *map;
	struct ss_table *table, *tbl;
	int err, cpu;

	ss_log(debug, "allocating map: attr = %p, size = %lu", attr,
	       sizeof(*map));
	map = kvzalloc(sizeof(*map), GFP_USER | __GFP_NOWARN);
	if (map == NULL) {
		ss_log(err, "failed to allocate map");
		err = -ENOMEM;
		goto err;
	}

	ss_log(debug, "allocating table: size = %lu", sizeof(*table));
	table = alloc_percpu_gfp(typeof(*table),
				 GFP_USER | __GFP_NOWARN | __GFP_ZERO);
	if (table == NULL) {
		ss_log(err, "failed to allocate table");
		err = -ENOMEM;
		goto err_free_map;
	}
	for_each_possible_cpu(cpu) {
		tbl = per_cpu_ptr(table, cpu);
		ss_log(debug, "initializing table for CPU %d: tbl = %p", cpu,
		       tbl);
		err = bpf_mem_alloc_init(&tbl->element_mem_alloc,
					 sizeof(struct ss_element), false);
		if (err) {
			ss_log(err,
			       "failed to initialize (element) BPF memory allocator for CPU %d",
			       cpu);
			goto err_free_map;
		}
		err = bpf_mem_alloc_init(&tbl->bucket_mem_alloc,
					 sizeof(struct ss_bucket), false);
		if (err) {
			ss_log(err,
			       "failed to initialize (bucket) BPF memory allocator for CPU %d",
			       cpu);
			goto err_free_map;
		}
		hash_init(tbl->elements);
		INIT_LIST_HEAD(&tbl->buckets);
	}
	map->table = table;

	return (struct bpf_map *)map;

err_free_map:
	kvfree(map);
err:
	return ERR_PTR(err);
}

static inline void __ss_element_free(struct ss_table *table,
				     struct ss_element *element)
{
	ss_log(debug, "freeing element: table = %p, element = %p", table,
	       element);
	bpf_mem_cache_free(&table->element_mem_alloc, element);
}

static inline void __ss_bucket_free(struct ss_table *table,
				    struct ss_bucket *bucket)
{
	ss_log(debug, "freeing bucket: table = %p, bucket = %p", table, bucket);
	bpf_mem_cache_free(&table->bucket_mem_alloc, bucket);
}

static void ss_free(struct bpf_map *map)
{
	struct ss_table_bpf_map *ss_map = (struct ss_table_bpf_map *)map;
	struct ss_table *table, *tbl;
	struct ss_element *element;
	struct ss_bucket *bucket;
	int cpu, bkt;

	if (ss_map == NULL) {
		ss_log(debug, "map is NULL; ignoring");
		return;
	}

	table = ss_map->table;
	for_each_possible_cpu(cpu) {
		tbl = per_cpu_ptr(table, cpu);
		ss_log(debug, "cleaning up table for CPU %d: tbl = %p", cpu,
		       tbl);
		hash_for_each(tbl->elements, bkt, element, hlist) {
			__ss_element_free(tbl, element);
		}
		bpf_mem_alloc_destroy(&tbl->element_mem_alloc);
		list_for_each_entry(bucket, &tbl->buckets, list) {
			__ss_bucket_free(tbl, bucket);
		}
		bpf_mem_alloc_destroy(&tbl->bucket_mem_alloc);
	}
	ss_log(debug, "freeing table: table = %p", table);
	free_percpu(table);

	ss_log(debug, "freeing map: map = %p", map);
	kvfree(ss_map);
}

static void *ss_lookup_elem(struct bpf_map *map, void *key)
{
	/* TODO: */
	return ERR_PTR(-ENOTSUPP);
}

static int ss_increment(struct ss_table *table, void *key)
{
	struct ss_element *element = NULL;
	struct ss_bucket *bucket, *neighbor_bucket, *new_bucket;
	ss_count_t value;
	u32 hash;
	int ret = 0;

	/* Step 1: Find the element; replace/create if not found */
	hash = xxh32(key, SS_KEY_SIZE, SS_HASH_SEED);
	ss_log(debug, "looking for existing key: key = %p, hash = 0x%08x", key,
	       hash);
	hash_for_each_possible(table->elements, element, hlist, hash) {
		/* Step 1, case 1: Found the element */
		if (memcmp(element->key, key, SS_KEY_SIZE) == 0) {
			bucket = element->parent;
			ss_log(debug,
			       "found existing key: element = %p, bucket = %p",
			       element, bucket);
			break;
		}
	}
	if (element == NULL) {
		/* Step 1, case 2: Key not found and another element is replaced */
		if (table->size >= SS_CAPACITY) {
			ss_log(debug,
			       "replacing element as table is full and key is not found");

			bucket = list_first_entry(&table->buckets,
						  struct ss_bucket, list);
			element = list_first_entry(&bucket->children,
						   struct ss_element, list);
			memcpy(element->key, key, SS_KEY_SIZE);

			ss_log(debug,
			       "replaced element key in bucket: element = %p, bucket = %p",
			       element, bucket);

		} else { /* Step 1, case 3: Key not found and a new element is created */
			ss_log(debug, "creating element as key is not found");

			bucket = NULL;
			element = __ss_element_alloc(table);
			if (element == NULL) {
				ss_log(err, "failed to allocate new element");
				ret = -ENOMEM;
				goto out;
			}
			memcpy(element->key, key, SS_KEY_SIZE);

			ss_log(debug, "created element: element = %p", element);
		}
	}

	/* Step 2: Find the new bucket; create if required */
	if (bucket != NULL) {
		neighbor_bucket = list_is_last(&bucket->list, &table->buckets) ?
					  NULL :
					  list_next_entry(bucket, list);
		value = bucket->value;
	} else { /* if the element is newly created, use the first bucket as "neighbor" (candidate of new bucket) */
		neighbor_bucket = list_empty(&table->buckets) ?
					  NULL :
					  list_first_entry(&table->buckets,
							   struct ss_bucket,
							   list);
		value = 0;
	}
	if (neighbor_bucket != NULL && neighbor_bucket->value == value + 1) {
		ss_log(debug,
		       "using existing neighbor bucket: neighbor_bucket = %p",
		       neighbor_bucket);
		new_bucket = neighbor_bucket;
	} else {
		ss_log(debug,
		       "creating new bucket as the neighbor is not eligible: neighbor_bucket = %p, neighbor_bucket->value = %u, value = %u",
		       neighbor_bucket,
		       neighbor_bucket != NULL ? neighbor_bucket->value : -1,
		       value + 1);
		new_bucket = __ss_bucket_alloc(table);
		if (new_bucket == NULL) {
			ss_log(err, "failed to allocate new bucket");
			ret = -ENOMEM;
			goto out;
		}
		new_bucket->value = value + 1;
		list_add(&new_bucket->list,
			 bucket != NULL ? &bucket->list : &table->buckets);
		ss_log(debug,
		       "created new bucket: new_bucket = %p, new_bucket->value = %u",
		       new_bucket, new_bucket->value);
	}

	/* Step 3: Move the element from the old bucket (if exist) to the new bucket */
	if (bucket != NULL) {
		ss_log(debug,
		       "removing element from bucket: element = %p, bucket = %p, bucket->value = %u",
		       element, bucket, value);
		list_del(&element->list);
		if (list_empty(&bucket->children)) {
			ss_log(debug,
			       "removing empty bucket: bucket = %p, bucket->value = %u",
			       bucket, value);
			list_del(&bucket->list);
			__ss_bucket_free(table, bucket);
		}
	}
	ss_log(debug, "adding element to bucket: element = %p, new_bucket = %p",
	       element, new_bucket);
	list_add(&element->list, &new_bucket->children);
	element->parent = new_bucket;

	/* Step 4: Remove (if required) and add the element in the hash table */
	if (bucket != NULL) {
		ss_log(debug,
		       "removing element from hash table: element = %p, bucket = %p, bucket->value = %u",
		       element, bucket, value);
		hash_del(&element->hlist);
	}
	ss_log(debug,
	       "adding element to hash table: element = %p, new_bucket = %p",
	       element, new_bucket);
	hash_add(table->elements, &element->hlist, hash);

	/* Step 5: Update the table size */
	if (bucket == NULL) {
		table->size++;
		ss_log(debug, "incremented table size: size = %lu",
		       table->size);
	}

out:
	return ret;
}

long ss_update_elem(struct bpf_map *map, void *key, void *value, u64 flags)
{
	struct ss_table_bpf_map *ss_map = (struct ss_table_bpf_map *)map;
	struct ss_table *table;
	int ret = 0;

	if (ss_map == NULL) {
		ret = -EINVAL;
		goto out;
	}

	table = this_cpu_ptr(ss_map->table);
	ret = ss_increment(table, key);

out:
	return ret;
}

uint64_t ss_mem_usage(const struct bpf_map *map)
{
	/* FIXME: This is estimated max usage */
	return sizeof(struct ss_table_bpf_map) +
	       num_possible_cpus() *
		       (sizeof(struct ss_table) +
			SS_CAPACITY * (sizeof(struct ss_table) +
				       sizeof(struct ss_element)));
}

static struct bpf_map_ops ss_ops = {
	.map_alloc_check = ss_alloc_check,
	.map_alloc = ss_alloc,
	.map_free = ss_free,
	.map_lookup_elem = ss_lookup_elem,
	.map_update_elem = ss_update_elem,
	.map_mem_usage = ss_mem_usage,
};

static int ss_initialize(void)
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

	ss_log(debug, "try module get");
	if (!try_module_get(THIS_MODULE)) {
		ret = -ENODEV;
		ss_log(err, "failed to take module");
		goto out;
	}

	/*testing alloc here*/
	ss_log(debug, "start testing alloc");

	attr.key_size = sizeof(struct pkt_5tuple);
	attr.value_size = sizeof(ss_count_t);
	attr.max_entries = SS_CAPACITY;

	if ((ret = ss_alloc_check(&attr))) {
		ss_log(err, "failed to check alloc: %d", ret);
		goto out_put_module;
	}

	map = ss_alloc(&attr);
	if (IS_ERR_OR_NULL(map)) {
		ret = PTR_ERR(map);
		ss_log(err, "failed to alloc map: %d", ret);
		goto out_put_module;
	}
	ss_log(debug, "testing alloc success");
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

	ss_log(debug, "start testing free");
	/*testing free here*/
	map = (struct bpf_map *)file->private_data;
	ss_log(debug, "testing free");
	ss_free(map);
	ss_log(debug, "testing free success");
	module_put(THIS_MODULE);
	return 0;
}

static ssize_t __testing_operation(struct file *flip, char __user *ubuf,
				   size_t count, loff_t *ppos)
{
	/* testing data structure operation*/
	struct bpf_map *map;
	int ret = 0, i;

	ss_log(debug, "testing space saving operation");
	map = (struct bpf_map *)(flip->private_data);

	struct pkt_5tuple pkts[SS_CAPACITY + 8];
	ss_count_t dummy = 0;
	get_random_bytes(pkts, sizeof(pkts));

	for (i = 0; i < SS_CAPACITY; ++i) {
		ss_log(debug, "inserting %d", i);
		ret = ss_update_elem(map, &pkts[i], &dummy, BPF_ANY);
		lkm_assert_eq(0, ret, "ss_update_elem should succeed");
	}

	for (i = 0; i < ARRAY_SIZE(pkts); ++i) {
		ss_log(debug, "updating %d", i);
		ret = ss_update_elem(map, &pkts[i], &dummy, BPF_ANY);
		lkm_assert_eq(0, ret, "ss_update_elem should succeed");
	}

	ss_log(info, "testing space saving success");
	return 0; /*always not insert the mod*/

lkm_test_error:
	ss_log(err, "testing space saving failed with res %d", ret);
	return 0;
}

static struct proc_ops testing_ops = {
	.proc_open = __testing_alloc,
	.proc_read = __testing_operation,
	.proc_release = __testing_release,
};

static int ss_proc_init(void)
{
	ent = proc_create("testing_space_saving_list", 0440, NULL,
			  &testing_ops);
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
		ss_log(err, "failed to initialize");
		goto out;
	}

	if ((ret = bpf_register_static_cmap(&ss_ops, THIS_MODULE)) != 0) {
		ss_log(err, "failed to register static cmap");
		goto out;
	}

#ifdef SS_DEBUG
	if ((ret = ss_proc_init()) != 0) {
		ss_log(err, "failed to initialize proc");
		goto out;
	}
#endif

	ss_log(info, "initialized");

out:
	return ret;
}

static void __exit ss_exit(void)
{
#ifdef SS_DEBUG
	ss_proc_cleanup();
#endif
	bpf_unregister_static_cmap(THIS_MODULE);

	ss_log(info, "exiting");
}

/* Register module functions */
module_init(ss_init);
module_exit(ss_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cheng Jiantao, Yang Hanlin");
MODULE_DESCRIPTION("Space-Saving algorithm LKM implementation");
MODULE_VERSION("0.0.1");
