#include <linux/init.h> 
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/math.h>
#include "../cmap_common.h"
     
// extern int bpf_register_custom_map(struct bpf_custom_map_ops *cmap);
// extern void bpf_unregister_custom_map(struct bpf_custom_map_ops *cmap);

static int data; 

static void *empty_alloc(union bpf_attr *attr)
{
	//demo alloc we just alloc char[hello world]
	return &data;
}

static void empty_free(void *map) {
	return;
}

static void *empty_lookup_elem(void *map, void *key) {
	return NULL;
}

static int empty_update_elem(void *map, void *key, void *value, u64 flag) 
{
	return 0;
}

static int empty_delete_elem(void *map, void *key) {
	return 0;
}

static struct bpf_custom_map_ops empty_ops = {
	.cmap_alloc = empty_alloc,
	.cmap_free = empty_free,
	.cmap_lookup_elem = empty_lookup_elem,
	.cmap_update_elem = empty_update_elem,
	.cmap_delete_elem = empty_delete_elem,
	.name = "empty_cmap",
	.owner = THIS_MODULE,
};

#define BASE_ID 10

#define BPF_CMAP_TYPES(fn)	\
fn(empty_ops)			\

BPF_CMAPS_SEC(empty_cmaps, BPF_CMAP_TYPES)

static int __init empty_cmaps_init(void) {
	pr_info("register empty_cmaps");
	init_cmaps_attr();
	return register_cmaps(empty_cmaps, __NR_BPF_CMAP_TYPE);
}

static void __exit empty_cmaps_exit(void) {
	pr_info("unregister empty_cmaps");
	unregister_cmaps(empty_cmaps, __NR_BPF_CMAP_TYPE);
}

/* Register module functions */
module_init(empty_cmaps_init);
module_exit(empty_cmaps_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chonepieceyb");
MODULE_DESCRIPTION("A simple BPF_CUSTOM_MAP demo.");
MODULE_VERSION("0.01");
