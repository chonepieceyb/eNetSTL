#include "linux/bpf.h"
#include "linux/compiler_attributes.h"
#include <linux/bpf_mem_alloc.h>
#include "linux/gfp_types.h"
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/random.h>
#include <linux/slab.h>

#define MAX_ENTRY 100000
#define RAND_MAX 2147483647
#define MAX_SKIPLIST_HEIGHT 8

#define TEST_RANGE 20
// #define USE_DEBUG

extern int bpf_register_static_cmap(struct bpf_map_ops *map,
				    struct module *onwer);
extern void bpf_unregister_static_cmap(struct module *onwer);
extern void bpf_map_area_free(void *area);
extern void *bpf_map_area_alloc(u64 size, int numa_node);

typedef struct sl_entry {
	__u64 key;
	__u64 value;
	int height;
	struct sl_entry *next[MAX_SKIPLIST_HEIGHT];
} sl_entry;

struct static_sl_map {
	struct bpf_map map;
	sl_entry *skiplist;
	__u32 entry_count;
	struct bpf_mem_alloc ma;
};

static inline void random(int *num)
{
	get_random_bytes(num, sizeof(int));
}

int grand(int max)
{
	int result = 1;
	int random_num;
	random(&random_num);

	while (result < max && (random_num > RAND_MAX / 2)) {
		++result;
		random(&random_num);
	}

	return result;
}

int skip_list_alloc_check(union bpf_attr *attr)
{
	if (attr->max_entries > MAX_ENTRY) {
		return -EINVAL;
	}
	return 0;
}

static struct bpf_map *skip_list_alloc(union bpf_attr *attr)
{
	struct static_sl_map *skiplist_map;
	void *res_ptr;

	skiplist_map =
		bpf_map_area_alloc(sizeof(struct static_sl_map), NUMA_NO_NODE);
	if (skiplist_map == NULL) {
		return ERR_PTR(-ENOMEM);
	}

	if (bpf_mem_alloc_init(&skiplist_map->ma, sizeof(sl_entry), false)) {
		/* alloc mem_alloc_cache*/
		res_ptr = ERR_PTR(-ENOMEM);
		goto free_bmap;
	}

	skiplist_map->skiplist = bpf_mem_cache_alloc(&skiplist_map->ma);
	if (skiplist_map->skiplist == NULL) {
		res_ptr = ERR_PTR(-ENOMEM);
		goto free_ma;
	}

	skiplist_map->skiplist->height = MAX_SKIPLIST_HEIGHT;
	skiplist_map->entry_count = 0;
	return (struct bpf_map *)skiplist_map;

free_ma:;
	bpf_mem_alloc_destroy(&skiplist_map->ma);
free_bmap:;
	bpf_map_area_free(skiplist_map);
	return res_ptr;
}

static void skip_list_free(struct bpf_map *map)
{
	struct static_sl_map *skip_list_map;
	if (map == NULL) {
		return;
	}
	skip_list_map = container_of(map, struct static_sl_map, map);

	sl_entry *current_entry = skip_list_map->skiplist;
	sl_entry *next_entry = NULL;
	while (current_entry) {
		next_entry = current_entry->next[0];
		bpf_mem_cache_free(&skip_list_map->ma, current_entry);
		current_entry = NULL;
		current_entry = next_entry;
	}

	bpf_mem_alloc_destroy(&skip_list_map->ma);
	bpf_map_area_free(skip_list_map);
	return;
}

static void *skip_list_lookup_elem(struct bpf_map *map, void* key_ptr)
{
	struct static_sl_map *skip_list_map =
		container_of(map, struct static_sl_map, map);
	sl_entry *head = skip_list_map->skiplist;

	sl_entry *curr = head;
	int level = head->height - 1;

	__u64 key = *(__u64 *)key_ptr;

	// Find the position where the key is expected
	while (curr != NULL && level >= 0) {
		if (curr->next[level] == NULL) {
			--level;
		} else {

			if (curr->next[level]->key == key) { // Found a match
				return &(curr->next[level]->value);
			} else if (curr->next[level]->key > key) { // Drop down a level
				--level;
			} else { // Keep going at this level
				curr = curr->next[level];
			}
		}
	}
	// Didn't find it
	return NULL;
}

static long skip_list_update_elem(struct bpf_map *map, void* key_ptr, void* value_ptr,
				  u64 flag)
{
	struct static_sl_map *skip_list_map =
		container_of(map, struct static_sl_map, map);
	sl_entry *head = skip_list_map->skiplist;

	sl_entry *prev[MAX_SKIPLIST_HEIGHT];
	sl_entry *curr = head;
	int level = head->height - 1;

	__u64 key = *(__u64 *)key_ptr;
	__u64 value = *(__u64 *)value_ptr;

	// Find the position where the key is expected
	while (curr != NULL && level >= 0) {
		prev[level] = curr;
		if (curr->next[level] == NULL) {
			--level;
		} else {
			if (curr->next[level]->key == key) { // Found a match, replace the old value
				curr->next[level]->value = value;
				skip_list_map->entry_count++;
				return 0;
			} else if (curr->next[level]->key > key) { // Drop down a level
				--level;
			} else { // Keep going at this level
				curr = curr->next[level];
			}
		}
	}

	// Didn't find it, we need to insert a new entry
	sl_entry *new_entry = bpf_mem_cache_alloc(&skip_list_map->ma);
	new_entry->height = grand(head->height);
	new_entry->key = key;
	new_entry->value = value;
	int i;
	// Null out pointers above height
	for (i = MAX_SKIPLIST_HEIGHT - 1; i > new_entry->height; --i) {
		new_entry->next[i] = NULL;
	}
	// Tie in other pointers
	for (i = new_entry->height - 1; i >= 0; --i) {
		new_entry->next[i] = prev[i]->next[i];
		prev[i]->next[i] = new_entry;
	}
	skip_list_map->entry_count++;
	return 0;
}

static long skip_list_delete_elem(struct bpf_map *map, void *key_ptr)
{
	struct static_sl_map *skip_list_map =
		container_of(map, struct static_sl_map, map);
	sl_entry *head = skip_list_map->skiplist;

	sl_entry *prev[MAX_SKIPLIST_HEIGHT];
	sl_entry *curr = head;
	int level = head->height - 1;

	__u64 key = *(__u64 *)key_ptr;

	// Find the list node just before the condemned node at every
	// level of the chain
	int cmp = 1;
	while (curr != NULL && level >= 0) {
		prev[level] = curr;
		if (curr->next[level] == NULL) {
			--level;
		} else {
			cmp = curr->next[level]->key - key;
			if (cmp >= 0) { // Drop down a level
				--level;
			} else { // Keep going at this level
				curr = curr->next[level];
			}
		}
	}

	// We found the match we want, and it's in the next pointer
	if (curr && !cmp) {
		sl_entry *condemned = curr->next[0];
		// Remove the condemned node from the chain
		int i;
		for (i = condemned->height - 1; i >= 0; --i) {
			prev[i]->next[i] = condemned->next[i];
		}
		// Free it
		bpf_mem_cache_free(&skip_list_map->ma, condemned);
		condemned = NULL;
		return 0;
	}
	return -ENOENT;
}

static u64 skip_list_mem_usage(const struct bpf_map *map)
{
	struct static_sl_map *skip_list_map =
		container_of(map, struct static_sl_map, map);
	return skip_list_map->entry_count * sizeof(sl_entry);
}

static struct bpf_map_ops cmap_ops = { .map_alloc_check = skip_list_alloc_check,
				       .map_alloc = skip_list_alloc,
				       .map_free = skip_list_free,
				       .map_lookup_elem = skip_list_lookup_elem,
				       .map_update_elem = skip_list_update_elem,
				       .map_delete_elem = skip_list_delete_elem,
				       .map_mem_usage = skip_list_mem_usage };

#ifdef USE_DEBUG
/* proc fs test API */

#include "../test_helpers.h"
#include <linux/proc_fs.h>

static struct proc_dir_entry *ent;

static int testing_alloc(struct inode *inode, struct file *filp)
{
	struct bpf_map *map;
	if (!try_module_get(THIS_MODULE)) {
		return -ENODEV;
	}
	/*testing alloc here*/
	pr_info("start testing alloc skip_list map");

	union bpf_attr test_attr = {
		.key_size = sizeof(__u32),
		.value_size = sizeof(__u32),
		.max_entries = MAX_ENTRY,
		.map_flags = 0,
	};

	map = skip_list_alloc(&test_attr);

	if (IS_ERR_OR_NULL(map)) {
		return PTR_ERR(map);
	}

	filp->private_data = (void *)map;
	return 0;
}

static int testing_release(struct inode *inode, struct file *file)
{
	/*testing free here*/
	struct bpf_map *map = (struct bpf_map *)file->private_data;
	skip_list_free(map);
	module_put(THIS_MODULE);
	return 0;
}

static ssize_t testing_operation(struct file *flip, char __user *ubuf,
				 size_t count, loff_t *ppos)
{
	pr_info("----start testing skip_list----\n");
	/* testing data structure operation*/
	struct bpf_map *map;
	map = (struct bpf_map *)(flip->private_data);

	int add_res[TEST_RANGE] = { 0 };
	int delete_res[TEST_RANGE] = { 0 };
	int lookup_res[TEST_RANGE] = { 0 };

	for (int i = 0; i < TEST_RANGE; i ++) {
		preempt_disable();
		int ret = skip_list_update_elem(map, (void *)&i,
						(void *)&i, 0);
		preempt_enable();
		if (ret == 0) {
			add_res[i] = 1;
		}
	}

	for (int i = 0; i < TEST_RANGE; i += 2) {
		preempt_disable();
		int ret = skip_list_delete_elem(map, (void *)&i);
		preempt_enable();
		if (ret == 0) {
			delete_res[i] = 1;
		}
	}

	for (int i = 0; i < TEST_RANGE; i++) {
		preempt_disable();
		__u32 *res = skip_list_lookup_elem(map, (void *)&i);
		preempt_enable();
		if (res != NULL) {
			lookup_res[i] = 1;
		}
	}

	for (int i = 0; i < TEST_RANGE; i++) {
		pr_info("add_res[%d]: %d, delete_res[%d]: %d, lookup_res[%d]: %d\n", i, add_res[i], i, delete_res[i], i, lookup_res[i]);
	}

	pr_info("----testing skip_list success----\n");

	return 0; /*always not insert the mod*/

lkm_test_error:
	pr_err("testing skip_list  failed \n");
	return 0;
}

static struct proc_ops testing_ops = {
	.proc_open = testing_alloc,
	.proc_read = testing_operation,
	.proc_release = testing_release,
};

//extern int bpf_register_static_cmap(struct bpf_map_ops *map, struct module *onwer);
//extern void bpf_unregister_static_cmap(struct module *onwer);

static int __init static_cmap_skip_list_init(void)
{
	ent = proc_create("skip_list_test", 0440, NULL, &testing_ops);
	if (IS_ERR_OR_NULL(ent))
		return -2;
	pr_info("register static skip_list_cmaps");
	return bpf_register_static_cmap(&cmap_ops, THIS_MODULE);
}

static void __exit static_cmap_skip_list_exit(void)
{
	proc_remove(ent);
	pr_info("unregister static skip_list_cmaps");
	bpf_unregister_static_cmap(THIS_MODULE);
}

#else
static int __init static_cmap_skip_list_init(void)
{
	pr_info("register static skip_list_scmaps");
	return bpf_register_static_cmap(&cmap_ops, THIS_MODULE);
}

static void __exit static_cmap_skip_list_exit(void)
{
	pr_info("unregister static skip_list_scmaps");
	bpf_unregister_static_cmap(THIS_MODULE);
}
#endif

/* Register module functions */
module_init(static_cmap_skip_list_init);
module_exit(static_cmap_skip_list_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("LunqiZhao");
MODULE_DESCRIPTION("DPDK skip_list implementation.");
MODULE_VERSION("0.01");