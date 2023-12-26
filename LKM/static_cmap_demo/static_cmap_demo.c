#include <linux/init.h> 
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/bpf.h>

extern int bpf_register_static_cmap(struct bpf_map_ops *map, struct module *onwer);
extern void bpf_unregister_static_cmap(struct module *onwer);
extern void bpf_map_area_free(void *area);
extern void *bpf_map_area_alloc(u64 size, int numa_node);

static const char* hello_world = "bpf custom map demo hello world\n";
// extern int bpf_register_custom_map(struct bpf_custom_map_ops *cmap);
// extern void bpf_unregister_custom_map(struct bpf_custom_map_ops *cmap);

struct static_demo_map {
	struct bpf_map map;
	//ECLARE_FLEX_ARRAY(char, data);
	char data[64];
};

int demo_alloc_check(union bpf_attr *attr) {
	return 0;
}

static struct bpf_map *demo_alloc(union bpf_attr *attr)
{
	//demo alloc we just alloc char[hello world]
	struct static_demo_map *map;
	map = bpf_map_area_alloc(sizeof(struct static_demo_map), NUMA_NO_NODE);
	if (map == NULL) {
		return ERR_PTR(-ENOMEM);
	}
        strcpy(map->data, hello_world);
	return (struct bpf_map*)map;
}

static void demo_free(struct bpf_map *map) {
	bpf_map_area_free(map);
}

static void* demo_lookup_elem(struct bpf_map *map, void *key) 
{
	struct static_demo_map *demo_map = (struct static_demo_map *)map;
	return &demo_map->data;
}

static u64 demo_mem_usage(const struct bpf_map *map) 
{
	return 64;
}

static struct bpf_map_ops cmap_ops = {
	.map_alloc_check = demo_alloc_check,
	.map_alloc = demo_alloc,
	.map_free = demo_free,
	.map_lookup_elem = demo_lookup_elem,
	.map_mem_usage = demo_mem_usage
};

//extern int bpf_register_static_cmap(struct bpf_map_ops *map, struct module *onwer);
//extern void bpf_unregister_static_cmap(struct module *onwer);

static int __init static_cmap_demo_init(void) {
	pr_info("register static demo_cmaps");
	return bpf_register_static_cmap(&cmap_ops, THIS_MODULE);
}

static void __exit static_cmap_demo_exit(void) {
	pr_info("unregister static demo_cmaps");
	bpf_unregister_static_cmap(THIS_MODULE);
}

/* Register module functions */
module_init(static_cmap_demo_init);
module_exit(static_cmap_demo_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chonepieceyb");
MODULE_DESCRIPTION("A simple BPF_CUSTOM_MAP demo.");
MODULE_VERSION("0.01");