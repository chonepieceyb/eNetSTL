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

struct static_empty_map {
	struct bpf_map map;
	//ECLARE_FLEX_ARRAY(char, data);
	int data;
};


int empty_alloc_check(union bpf_attr *attr) {
	return 0;
}

static struct bpf_map *empty_alloc(union bpf_attr *attr)
{
	//demo alloc we just alloc char[hello world]
	struct static_empty_map *map;
	map = bpf_map_area_alloc(sizeof(struct static_empty_map), NUMA_NO_NODE);
	if (map == NULL) {
		return ERR_PTR(-ENOMEM);
	}
        map->data = 1;
	return (struct bpf_map*)map;
}

static void empty_free(struct bpf_map *map) {
	bpf_map_area_free(map);
}

static void* empty_lookup_elem(struct bpf_map *map, void *key) 
{
	struct static_empty_map *empty_nap = (struct static_empty_map*)map;
	return &empty_nap->data;
}

static long empty_update_elem(struct bpf_map *map, void *key, void *value, u64 flags) 
{
	return 0;
}

static long empty_delete_elem(struct bpf_map *map, void *key) {
	return 0;
}

static u64 empty_mem_usage(const struct bpf_map *map) 
{
	return 4;
}

static struct bpf_map_ops empty_ops = {
	.map_alloc = empty_alloc,
	.map_free = empty_free,
	.map_lookup_elem = empty_lookup_elem,
	.map_update_elem = empty_update_elem,
	.map_delete_elem = empty_delete_elem,
	.map_mem_usage = empty_mem_usage
};

static int __init empty_cmaps_init(void) {
	pr_info("register static empty_cmaps");
	return bpf_register_static_cmap(&empty_ops, THIS_MODULE);
}

static void __exit empty_cmaps_exit(void) {
	pr_info("unregister static empty_cmaps");
	bpf_unregister_static_cmap(THIS_MODULE);
}

/* Register module functions */
module_init(empty_cmaps_init);
module_exit(empty_cmaps_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chonepieceyb");
MODULE_DESCRIPTION("A simple BPF_CUSTOM_MAP demo.");
MODULE_VERSION("0.01");