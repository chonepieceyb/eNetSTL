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
#define MAX_SKIPLIST_HEIGHT 16

#define TEST_RANGE 20
// #define USE_DEBUG

extern int bpf_register_static_cmap(struct bpf_map_ops *map,
				    struct module *onwer);
extern void bpf_unregister_static_cmap(struct module *onwer);
extern void bpf_map_area_free(void *area);
extern void *bpf_map_area_alloc(u64 size, int numa_node);

// #define MEM_CMP_FUNC __builtin_memcpy
#define MEM_CMP_FUNC memcmp_byte
static int memcmp_byte(void *a, void *b, __u64 size) {
	__u8 *a_ptr = (__u8 *)a;
	__u8 *b_ptr = (__u8 *)b;
	for (int i = 0; i < size; i++) {
		if (a_ptr[i] != b_ptr[i]) {
			return a_ptr[i] - b_ptr[i];
		}
	}
	return 0;
}
struct pkt_5tuple {
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	uint8_t proto;
} __attribute__((packed));

struct pkt_5tuple_with_pad {
	__u8 pad[30];
	__u16 key;
} __attribute__((packed));

struct value_with_pad {
	__u8 pad[120];
	__u64 data;
} __attribute__((packed));

typedef struct sl_entry {
	struct pkt_5tuple_with_pad key;
	struct value_with_pad value;
	int ref_cnt;
	int height;
	struct sl_entry *next[MAX_SKIPLIST_HEIGHT];
	int hit_cnt;
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

noinline sl_entry* ptr_get_next(sl_entry *parent, u32 idx)
{
	if (idx >= MAX_SKIPLIST_HEIGHT) {
		return NULL;
	}
	
	sl_entry *next_node = parent->next[idx & (MAX_SKIPLIST_HEIGHT - 1)];
	if (next_node == NULL) 
		return NULL;
	next_node->ref_cnt++;

	return next_node;
}

noinline void ptr_release_node(sl_entry *node)
{
	if (node == NULL) {
		return;
	}

	if (unlikely((--node->ref_cnt) == 0)) {
		preempt_disable();
		node->hit_cnt ++;
		preempt_enable();
	}
}

static void *skip_list_lookup_elem(struct bpf_map *map, void* key_ptr)
{
	struct static_sl_map *skip_list_map =
		container_of(map, struct static_sl_map, map);
	sl_entry *head = skip_list_map->skiplist;

	sl_entry *curr = head;
	int level = head->height - 1;

	struct pkt_5tuple_with_pad key = *(struct pkt_5tuple_with_pad *)key_ptr;
	// pr_info("--start search key: %llu--", key.key);
	// Find the position where the key is expected
	while (curr != NULL && level >= 0) {
		if (ptr_get_next(curr, level) == NULL) {
			--level;
			// pr_info("1. go to next level: %d", level);
		} else {
			sl_entry *next = ptr_get_next(curr, level);
			if (next == NULL) {
				pr_err("error at line %d", __LINE__);
			}
			struct pkt_5tuple_with_pad next_key = next->key;
			int cmp = MEM_CMP_FUNC(&next_key, &key, sizeof(struct pkt_5tuple_with_pad));
			// pr_info("cmp: %d", cmp);
			if (cmp == 0) { // Found a match
				// pr_info("--found key: %u at level: %d--", key.pkt.dst_port, level);
				ptr_release_node(curr);
				ptr_release_node(next);
				return &(curr->next[level]->value);
			} else if (cmp > 0) { // Drop down a level
				ptr_release_node(next);
				--level;
				// pr_info("2. go to next level: %d", level);
			} else { // Keep going at this level
				sl_entry *next = ptr_get_next(curr, level);
				if (next == NULL) {
					pr_err("error at line %d", __LINE__);
				}
				ptr_release_node(curr);
				curr = next;
				// pr_info("3. keep going at level: %d", level);
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

	struct pkt_5tuple_with_pad key = *(struct pkt_5tuple_with_pad *)key_ptr;
	struct value_with_pad value = *(struct value_with_pad *)value_ptr;

	// Find the position where the key is expected
	while (curr != NULL && level >= 0) {
                prev[level] = curr;
                if (ptr_get_next(curr, level) == NULL) {
			--level;
			// pr_info("1. go to next level: %d", level);
		} else {
                        sl_entry *next = ptr_get_next(curr, level);
			if (next == NULL) {
				pr_err("error at line %d", __LINE__);
			}
			struct pkt_5tuple_with_pad next_key = next->key;
			int cmp = MEM_CMP_FUNC(&next_key, &key, sizeof(struct pkt_5tuple_with_pad));
			// pr_info("cmp: %d", cmp);
			if (cmp == 0) { // Found a match
				// pr_info("--found key: %u at level: %d--", key.pkt.dst_port, level);
				ptr_release_node(curr);
				ptr_release_node(next);
				goto insert;
			} else if (cmp > 0) { // Drop down a level
				ptr_release_node(next);
				--level;
				// pr_info("2. go to next level: %d", level);
			} else { // Keep going at this level
				sl_entry *next = ptr_get_next(curr, level);
				if (next == NULL) {
					pr_err("error at line %d", __LINE__);
				}
				ptr_release_node(curr);
				curr = next;
				// pr_info("3. keep going at level: %d", level);
			}
                }
	}
insert:;
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

	struct pkt_5tuple_with_pad key = *(struct pkt_5tuple_with_pad *)key_ptr;

	// Find the list node just before the condemned node at every
	// level of the chain
	int cmp = 1;
	while (curr != NULL && level >= 0) {
		prev[level] = curr;
		if (curr->next[level] == NULL) {
			--level;
		} else {
			cmp = MEM_CMP_FUNC(&curr->next[level]->key, &key, sizeof(struct pkt_5tuple_with_pad));
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

/**
 * @brief add given value to the skip_list and pop first element
 * 
 * @param map 
 * @param value 
 * @param flags 
 * @return long 
 */
static long skip_list_push_pop_elem(struct bpf_map *map, void *value_ptr, u64 flags) {
	struct static_sl_map *skip_list_map =
		container_of(map, struct static_sl_map, map);
	sl_entry *head = skip_list_map->skiplist;

	sl_entry *prev[MAX_SKIPLIST_HEIGHT];
	sl_entry *curr = head;
	int level = head->height - 1;
	__u64 poped_elem = 0;

	if (head->next[0] == NULL) {
		pr_info("goto insert");
		goto insert;
	}
	struct pkt_5tuple_with_pad key = head->next[0]->key;

	// Find the list node just before the condemned node at every
	// level of the chain
	int cmp = 1;
	while (curr != NULL && level >= 0) {
		prev[level] = curr;
		if (curr->next[level] == NULL) {
			--level;
		} else {
			cmp = MEM_CMP_FUNC(&curr->next[level]->key, &key, sizeof(struct pkt_5tuple_with_pad));
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
		poped_elem = condemned->key.key;
		// Remove the condemned node from the chain
		int i;
		for (i = condemned->height - 1; i >= 0; --i) {
			prev[i]->next[i] = condemned->next[i];
		}
		// Free it
		bpf_mem_cache_free(&skip_list_map->ma, condemned);
		condemned = NULL;
	}

insert:;
	sl_entry *prev_2[MAX_SKIPLIST_HEIGHT];
	sl_entry *curr_2 = head;

	struct pkt_5tuple_with_pad key_2 = *(struct pkt_5tuple_with_pad *)value_ptr;
	struct value_with_pad value = *(struct value_with_pad *)value_ptr;

	// Find the position where the key is expected
	while (curr_2 != NULL && level >= 0) {
		prev_2[level] = curr_2;
		if (curr_2->next[level] == NULL) {
			--level;
		} else {
			cmp = MEM_CMP_FUNC(&curr->next[level]->key, &key_2, sizeof(struct pkt_5tuple_with_pad));
			if (cmp == 0) { // Found a match, replace the old value
				curr_2->next[level]->value = value;
				skip_list_map->entry_count++;
				return poped_elem;
			} else if (cmp > 0) { // Drop down a level
				--level;
			} else { // Keep going at this level
				curr_2 = curr_2->next[level];
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
		new_entry->next[i] = prev_2[i]->next[i];
		prev_2[i]->next[i] = new_entry;
	}
	skip_list_map->entry_count++;
	return poped_elem;
}


static long skip_list_pop_elem(struct bpf_map *map, void *val)
{

        struct static_sl_map *skip_list_map =
		container_of(map, struct static_sl_map, map);
	sl_entry *head = skip_list_map->skiplist;
        sl_entry *next = head->next[0];
        if (next == NULL)
                return 0;
        
        int height_next = next->height;
        for (int i = 0; i <  MAX_SKIPLIST_HEIGHT; i++) {
                if (i >= height_next) 
                        break;
                sl_entry *nnext = next->next[i];
                head->next[i] = nnext;
        }
        bpf_mem_cache_free(&skip_list_map->ma, next);
        skip_list_map->entry_count--;
        return 0;
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
				       .map_pop_elem = skip_list_pop_elem,
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

	// for (int i = 0; i < TEST_RANGE; i += 2) {
	// 	preempt_disable();
	// 	int ret = skip_list_delete_elem(map, (void *)&i);
	// 	preempt_enable();
	// 	if (ret == 0) {
	// 		delete_res[i] = 1;
	// 	}
	// }

	for (int i = 0; i < TEST_RANGE; i++) {
		preempt_disable();
		__u32 *res = skip_list_lookup_elem(map, (void *)&i);
		preempt_enable();
		if (res != NULL) {
			lookup_res[i] = 1;
		}
	}

	int i = 64;
	preempt_disable();
	__u32 *res = skip_list_lookup_elem(map, (void *)&i);
	preempt_enable();

	// for (int i = 0; i < TEST_RANGE; i++) {
	// 	pr_info("add_res[%d]: %d, delete_res[%d]: %d, lookup_res[%d]: %d\n", i, add_res[i], i, delete_res[i], i, lookup_res[i]);
	// }

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