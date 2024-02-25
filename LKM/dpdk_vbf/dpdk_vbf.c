#include <linux/init.h> 
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/bpf.h>
#include <linux/types.h>

#ifdef USE_SIMD_HASH
#include "../crc32hash.h"
#define HASH_FUNC rte_hash_crc
#else
#include "../fasthash.h"
#define HASH_FUNC fasthash32
#endif

extern int bpf_register_static_cmap(struct bpf_map_ops *map, struct module *onwer);
extern void bpf_unregister_static_cmap(struct module *onwer);
extern void bpf_map_area_free(void *area);
extern void *bpf_map_area_alloc(u64 size, int numa_node);

/* static vars */
#define MAX_ENTRY 1024
#define HASH_SEED_1 0xdeadbeef
#define HASH_SEED_2 0xaaaabbbb
#define MEMBER_NO_MATCH 0


/* datastruct params */
#define NUM_KEYS 1000
#define NUM_SET 8
#define NUM_KEYS_PER_BF 125
#define BITS 2048
#define __BIT_MASK 2047
#define NUM_HASHES 4
#define MUL_SHIFT 3
#define DIV_SHIFT 2

#define TEST_RANGE 20
// extern int bpf_register_custom_map(struct bpf_custom_map_ops *cmap);
// extern void bpf_unregister_custom_map(struct bpf_custom_map_ops *cmap);

/* bitwise operation */
static inline __u32
ctz32(__u32 v)
{
	return (unsigned int)__builtin_ctz(v);
}

struct vbf_memory {
	__u32 table[MAX_ENTRY];
};

struct static_vbf_map {
	struct bpf_map map;
	struct vbf_memory __percpu *table;
	__u32 lookup_res;
};

int vbf_alloc_check(union bpf_attr *attr) {
	if (attr->max_entries > MAX_ENTRY) {
		return -EINVAL;
	}
	return 0;
}

static struct bpf_map *vbf_alloc(union bpf_attr *attr)
{
	//demo alloc we just alloc char[hello world]
	struct static_vbf_map *vbf_map;
	void *res_ptr; 
	int cpu;

	vbf_map = bpf_map_area_alloc(sizeof(struct static_vbf_map), NUMA_NO_NODE);
	if (vbf_map == NULL) {
		return ERR_PTR(-ENOMEM);
	}

	vbf_map->table = __alloc_percpu_gfp(sizeof(struct vbf_memory), __alignof__(u64), GFP_USER | __GFP_NOWARN);
	if (vbf_map->table == NULL) {
		res_ptr = ERR_PTR(-ENOMEM);
		goto free_tmap;
	}
	for_each_possible_cpu(cpu) {
		struct vbf_memory *__vbf;
		__vbf = per_cpu_ptr(vbf_map->table, cpu);
		memset(__vbf, 0, sizeof(struct vbf_memory));
	}
	return (struct bpf_map*)vbf_map;
free_tmap:
	return res_ptr;
}

static void vbf_free(struct bpf_map *map) {
	struct static_vbf_map *vbf_map;
	if (map == NULL) {
		return;
	}
	vbf_map = container_of(map, struct static_vbf_map, map);

	free_percpu(vbf_map->table);
	bpf_map_area_free(vbf_map);
	return;
}

/* helper functions */
static __u32 test_bit_helper(__u32 *table, __u32 bit_loc) {
	__u32 a = 32 >> MUL_SHIFT;

	return (table[bit_loc >> DIV_SHIFT] >>
			((bit_loc & (a - 1)) << MUL_SHIFT)) & ((1ULL << NUM_SET) - 1);
}

static void set_bit_helper(__u32 *table, __u32 bit_loc, __s32 set) {
	if ((bit_loc >> DIV_SHIFT) >= MAX_ENTRY) {
		pr_err("bit_loc error at %d\n", __LINE__);
		return;
	}
	__u32 a = 32 >> MUL_SHIFT;
	table[bit_loc >> DIV_SHIFT] |=
			1UL << (((bit_loc & (a - 1)) << MUL_SHIFT) + set - 1);
}


static void* vbf_lookup_elem(struct bpf_map *map, void *key) 
{
	struct static_vbf_map *vbf_map = container_of(map, struct static_vbf_map, map);
	struct vbf_memory *__vbf = this_cpu_ptr(vbf_map->table);
	__u32 *table = __vbf->table;

	__u32 j;
	__u32 h1 = HASH_FUNC(key, map->key_size, HASH_SEED_1);
	__u32 h2 = HASH_FUNC(&h1, sizeof(__u32), HASH_SEED_2);
	__u32 mask = ~0;
	__u32 bit_loc;
	__u32 set_id;
	for (j = 0; j < NUM_HASHES; j++) {
		bit_loc = (h1 + j * h2) & __BIT_MASK;
		mask &= test_bit_helper(table, bit_loc);
	}

	if (mask) {
		/* TODD: original version pass a set_id pointer and alter it value, in custom map currently return not null if lookup scuess */
		set_id = ctz32(mask) + 1;
		return table;
	} else {
		set_id = MEMBER_NO_MATCH;
		return NULL;
	}
}

static long vbf_update_elem(struct bpf_map *map, void *key, void *value, u64 flag) {
	struct static_vbf_map *vbf_map = container_of(map, struct static_vbf_map, map);
	struct vbf_memory *__vbf = this_cpu_ptr(vbf_map->table);
	__u32 *table = __vbf->table;

	__u32 i, h1, h2;
	__u32 bit_loc;
	__u32 set_id = *(__u32 *)value;

	if (set_id > NUM_SET || set_id == MEMBER_NO_MATCH)
		return -1;

	h1 = HASH_FUNC(key, map->key_size, HASH_SEED_1);
	h2 = HASH_FUNC(&h1, sizeof(__u32), HASH_SEED_2);

	for (i = 0; i < NUM_HASHES; i++) {
		bit_loc = (h1 + i * h2) & __BIT_MASK;
		set_bit_helper(table, bit_loc, set_id);
	}
	return 0;
}

static u64 vbf_mem_usage(const struct bpf_map *map) 
{
	return sizeof(struct vbf_memory) * num_possible_cpus();
}


static struct bpf_map_ops cmap_ops = {
	.map_alloc_check = vbf_alloc_check,
	.map_alloc = vbf_alloc,
	.map_free = vbf_free,
	.map_lookup_elem = vbf_lookup_elem,
	.map_update_elem = vbf_update_elem,
	.map_mem_usage = vbf_mem_usage
};

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
	pr_info("start testing alloc vbf map");

	union bpf_attr test_attr = {
		.key_size = sizeof(__u32),
		.value_size = sizeof(__u32),
		.max_entries = MAX_ENTRY,
		.map_flags = 0,
	};
	
	map = vbf_alloc(&test_attr);

	if (IS_ERR_OR_NULL(map)) {
		return PTR_ERR(map);
	}

	filp->private_data = (void*)map;
	return 0;
}

static int testing_release(struct inode *inode, struct file *file)
{
	/*testing free here*/
	struct bpf_map *map = (struct bpf_map*)file->private_data;
	vbf_free(map);
	module_put(THIS_MODULE);
	return 0;
}

static ssize_t testing_operation(struct file *flip, char __user *ubuf, size_t count, loff_t *ppos) 
{
	pr_info("----start testing DPDK vBF----\n");
	/* testing data structure operation*/
	struct bpf_map *map;
	map = (struct bpf_map *)(flip->private_data);

	int add_res[TEST_RANGE] = {0};
	int lookup_res[TEST_RANGE] = {0};
	int set_id = 1;
	for (int i = 0; i < TEST_RANGE; i += 2) {
		preempt_disable();
		int ret = vbf_update_elem(map, (void*)&i, (void*)&set_id, 0);
		preempt_enable();
		if (ret == 0) {
			add_res[i] = 1;
		}
	}

	for (int i = 0; i < TEST_RANGE; i++) {
		preempt_disable();
		__u32 *res = vbf_lookup_elem(map, (void*)&i);
		preempt_enable();
		if (res != NULL) {
			lookup_res[i] = 1;
		}
		pr_info("lookup_res[%d]: %d\n", i, lookup_res[i]);
	}

	for (int i = 0; i < TEST_RANGE; i++) {
		if (add_res[i] != lookup_res[i]) {
			pr_err("vbf failed at %d, add_res: %d, lookup_res: %d\n", i, add_res[i], lookup_res[i]);
			goto lkm_test_error;
		}
	}

	pr_info("----testing DPDK vBF success----\n");

	return 0;      /*always not insert the mod*/

lkm_test_error:
	pr_err("testing DPDK vBF  failed \n");
	return 0;
}
 
static struct proc_ops testing_ops = 
{
	.proc_open = testing_alloc,
	.proc_read = testing_operation,
	.proc_release = testing_release,
};

//extern int bpf_register_static_cmap(struct bpf_map_ops *map, struct module *onwer);
//extern void bpf_unregister_static_cmap(struct module *onwer);

static int __init static_cmap_vbf_init(void) {
	ent = proc_create("vbf_test",0440,NULL,&testing_ops);
	if (IS_ERR_OR_NULL(ent))
		return -2;
	pr_info("register static vbf_cmaps");
	return bpf_register_static_cmap(&cmap_ops, THIS_MODULE);
}

static void __exit static_cmap_vbf_exit(void) {
	proc_remove(ent);
	pr_info("unregister static vbf_cmaps");
	bpf_unregister_static_cmap(THIS_MODULE);
}

#else
static int __init static_cmap_vbf_init(void) {
	pr_info("register static vbf_scmaps");
	return bpf_register_static_cmap(&cmap_ops, THIS_MODULE);
}

static void __exit static_cmap_vbf_exit(void) {
	pr_info("unregister static vbf_scmaps");
	bpf_unregister_static_cmap(THIS_MODULE);
}
#endif

/* Register module functions */
module_init(static_cmap_vbf_init);
module_exit(static_cmap_vbf_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("LunqiZhao");
MODULE_DESCRIPTION("DPDK vBF implementation.");
MODULE_VERSION("0.01");