#include <linux/bpf_mem_alloc.h>
#include <linux/init.h> 
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/math.h>
#include <linux/bpf.h>
     
// extern int bpf_register_custom_map(struct bpf_custom_map_ops *cmap);
// extern void bpf_unregister_custom_map(struct bpf_custom_map_ops *cmap);
extern int bpf_register_static_cmap(struct bpf_map_ops *map, struct module *onwer);
extern void bpf_unregister_static_cmap(struct module *onwer);
extern void bpf_map_area_free(void *area);
extern void *bpf_map_area_alloc(u64 size, int numa_node);

#define FRONT_TAIL_BIT_POS 0     //bit pos, set means front 
#define INS_LOOK_BIT_POS 1     //bit pos, set means insert

#define bktlist_lookup_flag(ins_look, front_tail)			\
({									\
	u32 __flags = 0;						\
	u32 __ins_look = !!(ins_look);					\
	u32 __front_tail = !!(front_tail);				\
	__flags |= (__ins_look << INS_LOOK_BIT_POS);			\
	__flags |= (__front_tail << FRONT_TAIL_BIT_POS);		\
})

#define bktlist_delete_flag(front_tail)				        \
({									\
	u32 __flags = 0;						\
	u32 __front_tail = !!(front_tail);				\
	__flags |= (__front_tail << FRONT_TAIL_BIT_POS);			\
})


#define bktlist_flag_lookup_front  bktlist_lookup_flag(0, 1)
#define bktlist_flag_lookup_tail   bktlist_lookup_flag(0, 0)
#define bktlist_flag_ins_front  bktlist_lookup_flag(1, 1)
#define bktlist_flag_ins_tail	bktlist_lookup_flag(1, 0)
#define bktlist_flag_delete_front	bktlist_delete_flag(1)
#define bktlist_flag_delete_tail	bktlist_delete_flag(0)

#define test_bktlist_flags_front(flags)					\
({					        			\
	bool __res;							\
	__res = ((u32)(flags) & (1U << (FRONT_TAIL_BIT_POS))) != 0; 	\
})

#define test_bktlist_flags_ins(flags)					\
({					        			\
	bool __res;							\
	__res = ((u32)(flags) & (1U << (INS_LOOK_BIT_POS))) != 0; 	\
})

enum bktlist_flags {
	BKTLIST_LOOKUP_FRONT = 0,
	BKTLIST_LOOKUP_TAIL,
	BKTLIST_INSERT_FRONT,
	BKTLIST_INSERT_TAIL,
	BKTLIST_DELETE_FRONT,
	BKTLIST_DELETE_TAIL,
};

struct bktlist_entry {
	struct list_head node;
	DECLARE_FLEX_ARRAY(char, data);
};

struct bktlist_map {
	struct bpf_map map;
	u32 cnt;
	struct bpf_mem_alloc ma;
	//struct list_head __percpu **bkts;  /* dynamic array of struct list_head __percpu *[dynamic_size] */
	DECLARE_FLEX_ARRAY(struct list_head __percpu *, bkts) ____cacheline_aligned_in_smp;
};

struct __bktlist_key_type {
	u32 idx;
	u32 flags; 
};

int bktlist_alloc_check(union bpf_attr *attr) {
	if (attr->key_size != sizeof(struct __bktlist_key_type)) {
		return -EINVAL;
	}
	if (attr->value_size < 4) {
		return -EINVAL;
	}
	return 0;
}

static __always_inline void __init_bkt_list(int cpu, struct bktlist_map *bmap, u32 max_entries) 
{
        u32 i;
	for (i = 0; i < max_entries; i++) {
		struct list_head *head = per_cpu_ptr(bmap->bkts[i], cpu);
		INIT_LIST_HEAD(head);
	}   
}

static __always_inline void __free_bkt_list_entries(int cpu, struct bktlist_map *bmap, u32 max_entries) 
{
        u32 i;
	/* free the list entry*/
	migrate_disable();	/*bpf_mem_cache_free relies on this*/
	for (i = 0; i < max_entries; i++) {
		struct list_head *head = per_cpu_ptr(bmap->bkts[i], cpu);
		struct bktlist_entry *entry, *n; 
		list_for_each_entry_safe(entry, n, head , node) {
                        /* node is allocated in bpf_lookup_elem(with flag set to insert), free here*/
                        list_del(&entry->node);
                        bpf_mem_cache_free(&bmap->ma, entry);
                }
	} 
	migrate_enable();
}

static __always_inline void __free_bkt_list(struct bktlist_map *bmap, u32 max_entries)
{
	u32 i;
        for (i = 0; i < max_entries; i++) {
                free_percpu(bmap->bkts[i]);
        }
	//bpf_map_area_free(bmap->bkts);
        return;
}

static __always_inline void free_bkt_list(struct bktlist_map *bmap, u32 max_entries) {
	int cpu; 
	for_each_possible_cpu(cpu) {
		__free_bkt_list_entries(cpu, bmap, max_entries);
	}
	__free_bkt_list(bmap, max_entries);
}

static __always_inline int __alloc_bkts(struct bktlist_map *bmap, u32 max_entries)
{
	u32 i;
	// bmap->bkts = bpf_map_area_alloc(sizeof(void*) * max_entries, NUMA_NO_NODE);
	// if (bmap->bkts == NULL) {
	// 	pr_err("failed to alloc bmap->bkt");
	// 	return -ENOMEM;
	// }
        for (i = 0; i < max_entries; i++) {
                bmap->bkts[i] = __alloc_percpu_gfp(sizeof(struct list_head), __alignof__(u64), GFP_USER | __GFP_NOWARN);
		if (bmap->bkts[i] == NULL) {
			goto err_free;
		}
        }
        return 0;
err_free:;
        __free_bkt_list(bmap, max_entries);
        return -ENOMEM;
}

static struct bpf_map *bktlist_alloc(union bpf_attr *attr)
{
	struct bktlist_map *bmap;
	void *res_ptr;
	u32 max_entries;
	int cpu;
	max_entries = attr->max_entries;
	u32 __value_size; 
	u64 map_size = sizeof(struct bktlist_map) + sizeof(void*) * max_entries;
	bmap = bpf_map_area_alloc(map_size, NUMA_NO_NODE);
	if (bmap == NULL) {
		return ERR_PTR(-ENOMEM);
	}

	__value_size = sizeof(struct bktlist_entry) + attr->value_size;
	pr_debug("bmap __value_size %u", __value_size);
	if (bpf_mem_alloc_init(&bmap->ma, __value_size, false)) {
		/* alloc mem_alloc_cache*/
		res_ptr = ERR_PTR(-ENOMEM);
		goto free_bmap;
	}

	if (__alloc_bkts(bmap, max_entries)) {
		res_ptr = ERR_PTR(-ENOMEM);
		goto free_ma;
	}

	/*init bkt list*/
	for_each_possible_cpu(cpu) {
		__init_bkt_list(cpu, bmap, max_entries);
	}

	bmap->cnt = 0;
	return (struct bpf_map*)bmap;

free_ma:;
	bpf_mem_alloc_destroy(&bmap->ma);
free_bmap:;
	bpf_map_area_free(bmap);
	return res_ptr;
}

static void bktlist_free(struct bpf_map *map) {
	/*
	*1. free list enties 
	*2. free bkt list 
	*3. free map 
	*/
	struct bktlist_map *bmap = container_of(map, struct bktlist_map, map);
	u32 max_entries = map->max_entries;
	free_bkt_list(bmap, max_entries);
	bpf_mem_alloc_destroy(&bmap->ma);
	bpf_map_area_free(bmap);
}

static __always_inline void* __insert_and_get(struct bktlist_map *bmap, u32 idx, bool front)
{
	struct list_head *head;
	struct bktlist_entry *new_entry;
	pr_debug("__insert_and_get");
	if (idx >= bmap->map.max_entries) {
		pr_debug("__lookup idx out of bound %u > %u", idx, bmap->map.max_entries);
		return NULL;
	}
	/*free in delete or freee*/
	new_entry = bpf_mem_cache_alloc(&bmap->ma);
	if (new_entry == NULL) {
		pr_debug("__insert_and_get failed to alloc new entry");
		return NULL;
	}
	bmap->cnt += 1;
	head = this_cpu_ptr(bmap->bkts[idx]);

	if (front) {
		list_add( &new_entry->node, head);
		pr_debug("__insert_and_get first entry");
	} else {
		list_add_tail(&new_entry->node, head);
		pr_debug("__insert_and_get last entry");
	}
	return (void*)new_entry->data;
}

static __always_inline void* __lookup(struct bktlist_map *bmap, u32 idx, bool front)
{
	struct list_head *head;
	struct bktlist_entry *entry;
	pr_debug("__lookup");
	if (idx >= bmap->map.max_entries) {
		pr_debug("__lookup idx out of bound");
		return NULL;
	}
	head = this_cpu_ptr(bmap->bkts[idx]);
	
	if (list_empty(head)) {
		pr_debug("__lookup list is empty");
		return NULL;
	}
		
	if (front) {
		entry = list_first_entry(head, struct bktlist_entry, node);
		pr_debug("__lookup get first entry");
	} else {
		entry = list_last_entry(head, struct bktlist_entry, node);
		pr_debug("__lookup get last entry");
	}
	return (void*)(entry->data);
}

static void* bktlist_lookup_elem(struct bpf_map *map, void *key) 
{
	struct bktlist_map *bmap = container_of(map, struct bktlist_map, map);
	struct __bktlist_key_type *__key = (struct __bktlist_key_type *)key;
	u32 idx = __key->idx, flags = __key->flags;
	bool front = test_bktlist_flags_front(flags);
	pr_debug("blklist lookup idx %u, flags %x", idx, flags);
	if (test_bktlist_flags_ins(flags)) {
		return __insert_and_get(bmap, idx, front);
	} else {
		return __lookup(bmap, idx, front);
	}
}

static long bktlist_delete_elem(struct bpf_map *map, void *key) 
{
	struct bktlist_map *bmap = container_of(map, struct bktlist_map, map);
	struct __bktlist_key_type *__key = (struct __bktlist_key_type *)key;
	u32 idx = __key->idx, flags = __key->flags;
	bool front = test_bktlist_flags_front(flags);
	struct list_head *head;
	struct bktlist_entry *del_entry;
	if (idx >= bmap->map.max_entries) {
		pr_debug("delete_elem idx out of bound");
		return -EINVAL;
	}

	head = this_cpu_ptr(bmap->bkts[idx]);
	if (list_empty(head)) {
		pr_debug("bktlist_delete_elem list is empty");
		return -ENOENT;
	}
		
	if (front) {
		del_entry = list_first_entry(head, struct bktlist_entry, node);
		pr_debug("bktlist_delete_elem delete first entry");
	} else {
		del_entry = list_last_entry(head, struct bktlist_entry, node);
		pr_debug("bktlist_delete_elem delet last entry");
	}
	list_del(&del_entry->node);
	/* free memory*/
	bpf_mem_cache_free(&bmap->ma, del_entry);
	bmap->cnt -= 1;
	return 0;
}

static u64 bktlist_mem_usage(const struct bpf_map *map) 
{
	struct bktlist_map *bmap = container_of(map, struct bktlist_map, map);
	u32 __value_size = sizeof(struct bktlist_entry) + map->value_size;
	return (u64)(bmap->cnt * __value_size);
}

#ifndef USE_DEBUG

static struct bpf_map_ops bktlist_ops = {
	.map_alloc_check = bktlist_alloc_check,
	.map_alloc = bktlist_alloc,
	.map_free = bktlist_free,
	.map_lookup_elem = bktlist_lookup_elem,
	.map_delete_elem = bktlist_delete_elem,
	.map_mem_usage = bktlist_mem_usage
};

static int __init bktlist_init(void) {
	pr_info("register static base bktlist");
	return bpf_register_static_cmap(&bktlist_ops, THIS_MODULE);
}

static void __exit bktlist_exit(void) {
	pr_info("unregister static base bktlist");
	bpf_unregister_static_cmap(THIS_MODULE);
}

#else
/* testing */

#include "../test_helpers.h"
#include <linux/proc_fs.h>

static struct proc_dir_entry *ent;
 
static int testing_alloc(struct inode *inode, struct file *filp)
{
        struct bpf_map *map;
	union bpf_attr attr; 
	memset(&attr, 0 , sizeof(attr));
        if (!try_module_get(THIS_MODULE)) {
                return -ENODEV;
        }
        /*testing alloc here*/
	attr.key_size = sizeof(struct __bktlist_key_type);
	attr.value_size = sizeof(u32);
	attr.max_entries = 2;
        pr_info("start testing alloc bktlist");
        map =  bktlist_alloc(&attr);

        if (IS_ERR_OR_NULL(map)) {
                return PTR_ERR(map);
        }
	map->key_size = attr.key_size;
	map->value_size = attr.value_size;
	map->max_entries = attr.max_entries;
        pr_info("alloc time bktlist map success");
        filp->private_data = (void*)map;
        return 0;
}
         
static int testing_release(struct inode *inode, struct file *file)
{
        /*testing free here*/
        struct bpf_map *map = (struct bpf_map*)file->private_data;
        bktlist_free(map);
        module_put(THIS_MODULE);
        return 0;
}

static ssize_t testing_operation(struct file *flip, char __user *ubuf, size_t count, loff_t *ppos) 
{
	/* testing data structure operation*/
	preempt_disable();
        struct bpf_map *map;
        struct __bktlist_key_type key;
	u32 *value;
        int res = 0;
	u32 front = 1;
	u32 tail = 1;

	memset(&key, 0, sizeof(key));
        pr_info("testing bktlist operation\n");
        map = (struct bpf_map *)(flip->private_data);
             
	//insert front 
	key.idx = 1;

	pr_info("testing ins front");
	key.flags = bktlist_flag_ins_front;
        value = bktlist_lookup_elem(map, (void*)&key);
	lkm_assert_neq(NULL, value, "bktlist failed to insert front");
	*value = front;

	pr_info("testing ins tail");
	key.flags = bktlist_flag_ins_tail;
        value = bktlist_lookup_elem(map, (void*)&key);
	lkm_assert_neq(NULL, value, "bktlist failed to insert tail");
	*value = tail;

	pr_info("testing lookup front");
	key.flags = bktlist_flag_lookup_front;
        value = bktlist_lookup_elem(map, (void*)&key);
	lkm_assert_neq(NULL, value, "bktlist failed to lookup front");
	lkm_assert_eq(front, *value, "bktlist lookup front incorrect");
	
	pr_info("testing lookup tail");
	key.flags = bktlist_flag_lookup_tail;
        value = bktlist_lookup_elem(map, (void*)&key);
	lkm_assert_neq(NULL, value, "bktlist failed to lookup tail");
	lkm_assert_eq(tail, *value, "bktlist lookup tail incorrect");

	pr_info("testing delete front");
	key.flags = bktlist_flag_delete_front;
        res = bktlist_delete_elem(map, (void*)&key);
	lkm_assert_eq(0, res, "bktlist failed to delete front");


	key.flags = bktlist_flag_lookup_front;
        value = bktlist_lookup_elem(map, (void*)&key);
	lkm_assert_eq(tail, *value, "bktlist delete front incorrect");

	//reins front
	key.flags = bktlist_flag_ins_front;
        value = bktlist_lookup_elem(map, (void*)&key);
	lkm_assert_neq(NULL, value, "bktlist failed to insert front");
	*value = front;


	pr_info("testing delete tail");
	key.flags = bktlist_flag_delete_tail;
        res = bktlist_delete_elem(map, (void*)&key);
	lkm_assert_eq(0, res, "bktlist failed to delete tail");

	key.flags = bktlist_flag_lookup_front;
        value = bktlist_lookup_elem(map, (void*)&key);
	lkm_assert_neq(NULL, value, "bktlist failed to lookup front");
	lkm_assert_eq(front, *value, "bktlist delete tail incorrect");


	key.idx = 0;
	pr_info("testing lookup front empty");
	key.flags = bktlist_flag_lookup_front;
        value = bktlist_lookup_elem(map, (void*)&key);
	lkm_assert_eq(NULL, value, "bktlist empty lookup front return not NULL");

	pr_info("testing lookup tail empty");
	key.flags = bktlist_flag_lookup_tail;
        value = bktlist_lookup_elem(map, (void*)&key);
	lkm_assert_eq(NULL, value, "bktlist empty lookup tail return not NULL");

	pr_info("testing delete empty front");
	key.flags = bktlist_flag_delete_front;
        res = bktlist_delete_elem(map, (void*)&key);
	lkm_assert_eq(-ENOENT, res, "bktlist delete empty front incorrect");

	pr_info("testing delete empty tail");
	key.flags = bktlist_flag_delete_tail;
        res = bktlist_delete_elem(map, (void*)&key);
	lkm_assert_eq(-ENOENT, res, "bktlist delete empty tail incorrect");

	preempt_enable();
        pr_info("testing bktlist success\n");
        return 0;      /*always not insert the mod*/

lkm_test_error:
	preempt_enable();
        pr_err("testing bktlist failed with res %d\n", res);
        return 0;
}
 
static struct proc_ops testing_ops = 
{
        .proc_open = testing_alloc,
        .proc_read = testing_operation,
        .proc_release = testing_release,
};

static int __init bktlist_init(void) 
{
        ent = proc_create("testing_bktlist",0440,NULL,&testing_ops);
        if (IS_ERR_OR_NULL(ent))
                return -2;
	return 0;
}


static void __exit bktlist_exit(void) {
        proc_remove(ent);
        return;
}

#endif

/* Register module functions */
module_init(bktlist_init);
module_exit(bktlist_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chonepieceyb");
MODULE_DESCRIPTION("Base bktlist implementation");
MODULE_VERSION("0.01");