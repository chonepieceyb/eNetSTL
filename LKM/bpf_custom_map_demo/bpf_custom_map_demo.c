#include <linux/init.h> 
#include <linux/module.h> 
#include <linux/printk.h>
#include <linux/bpf.h>
#include <linux/bpf_custom_map.h>
#include <linux/string.h>
#include <linux/math.h>
     
static const char* hello_world = "bpf custom map demo hello world\n";
#define ID 101

extern int bpf_register_custom_map(struct bpf_custom_map_ops *cmap);
extern void bpf_unregister_custom_map(struct bpf_custom_map_ops *cmap);

static void *demo_alloc(union bpf_attr *attr)
{
	//demo alloc we just alloc char[hello world]
	void *map_data; 
	map_data = kmalloc(roundup(strlen(hello_world) + 1, 8), GFP_KERNEL);
        strcpy(map_data, hello_world);
	return map_data;
}

static void demo_free(void *map) {
	kfree(map);
}

static void *demo_lookup_elem(void *map, void *key) {
	return map;
}

static struct bpf_custom_map_ops cmap_ops = {
	.cmap_alloc = demo_alloc,
	.cmap_free = demo_free,
	.cmap_lookup_elem = demo_lookup_elem,
        
        .id = ID,
	.name = "custom_map_demo",
	.owner = THIS_MODULE,
};


static int __init custom_map_demo_init(void) {
        int ret;
	ret = bpf_register_custom_map(&cmap_ops);
	if (ret < 0) {
		pr_err("failed to reigster custom_map_demo with id %d, err: %d\n", ID, ret);
		return -1;
	}
	pr_info("register custom_map_demo, id : %d\n", ID);
	return 0;
}

static void __exit custom_map_demo_exit(void) {
	bpf_unregister_custom_map(&cmap_ops);
        pr_info("unregister custom_map_demo id : %d\n", ID);
}

/* Register module functions */
module_init(custom_map_demo_init);
module_exit(custom_map_demo_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chonepieceyb");
MODULE_DESCRIPTION("A simple BPF_CUSTOM_MAP demo.");
MODULE_VERSION("0.01");
