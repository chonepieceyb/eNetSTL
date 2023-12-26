#include <linux/init.h> 
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/math.h>
#include "../cmap_common.h"
     
static const char* hello_world = "bpf custom map demo hello world\n";
// extern int bpf_register_custom_map(struct bpf_custom_map_ops *cmap);
// extern void bpf_unregister_custom_map(struct bpf_custom_map_ops *cmap);

static void *demo_alloc(union bpf_attr *attr)
{
	//demo alloc we just alloc char[hello world]
	void *map_data; 
	map_data = kmalloc(64, GFP_KERNEL);
        strcpy(map_data, hello_world);
	return map_data;
}

static void demo_free(void *map) {
	kfree(map);
}

static void *demo_lookup_elem(void *map, void *key) {
	return map;
}

static u64 demo_mem_usage(const void  *map) 
{
	return 64;
}

static struct bpf_custom_map_ops cmap_ops = {
	.cmap_alloc = demo_alloc,
	.cmap_free = demo_free,
	.cmap_lookup_elem = demo_lookup_elem,
	.cmap_mem_usage = demo_mem_usage,
	.name = "custom_map_demo",
	.owner = THIS_MODULE,
};

#define BASE_ID 100

#define BPF_CMAP_TYPES(fn)	\
fn(cmap_ops)			

BPF_CMAPS_SEC(demo_cmaps, BPF_CMAP_TYPES)

static int __init custom_map_demo_init(void) {
	pr_info("register demo_cmaps");
	init_cmaps_attr();
	return register_cmaps(demo_cmaps, __NR_BPF_CMAP_TYPE);
}

static void __exit custom_map_demo_exit(void) {
	pr_info("unregister demo_cmaps");
	unregister_cmaps(demo_cmaps, __NR_BPF_CMAP_TYPE);
}

/* Register module functions */
module_init(custom_map_demo_init);
module_exit(custom_map_demo_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chonepieceyb");
MODULE_DESCRIPTION("A simple BPF_CUSTOM_MAP demo.");
MODULE_VERSION("0.01");
