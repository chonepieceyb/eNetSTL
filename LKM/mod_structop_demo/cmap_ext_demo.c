#include "linux/err.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/bpf.h>
#include <linux/bpf_custom_map.h>
#include <linux/string.h>
#include <linux/math.h>
#include <linux/filter.h>
#include "mod_struct_ops_demo.h"
#include <linux/bpf_struct_ops_module.h>

// extern int bpf_register_custom_map(struct bpf_custom_map_ops *cmap);
// extern void bpf_unregister_custom_map(struct bpf_custom_map_ops *cmap);
extern int bpf_register_static_cmap(struct bpf_map_ops *map, struct module *onwer);
extern void bpf_unregister_static_cmap(struct module *onwer);
extern void bpf_map_area_free(void *area);
extern void *bpf_map_area_alloc(u64 size, int numa_node);

struct static_map_ext {
	struct bpf_map map;
	struct mod_struct_ops_ctx ctx;
	struct mod_struct_ops_demo *ext_ops;
};

// static DEFINE_SPINLOCK(ops_mutex);
// static struct mod_struct_ops_demo __rcu *ext_ops = NULL;

static struct mod_struct_ops_demo *bpf_ops = NULL;
static DEFINE_SPINLOCK(static_ops_lock);
static struct bpf_prog* hw_prog = NULL;


// static int empty_hello_world(struct mod_struct_ops_ctx *ctx) {
// 	ctx->val = 10001;
// 	return 0;
// }

// DEFINE_STATIC_CALL_RET0(__static_hello_world, empty_hello_world);

// static int static_hello_world(struct mod_struct_ops_ctx *ctx) {
// 	return static_call(__static_hello_world)(ctx);
// }

// void set_default_static_funcs(void) 
// {
// 	static_call_update(__static_hello_world, empty_hello_world);
// }

DEFINE_BPF_DISPATCHER(demo_hw)

void bpf_prog_change_hw(struct bpf_prog *prev_prog, struct bpf_prog *prog)
{
	bpf_dispatcher_change_prog(BPF_DISPATCHER_PTR(demo_hw), prev_prog, prog);
}

struct demo_hw_ctx {
	struct mod_struct_ops_ctx *ctx;
};

static u32 bpf_prog_run_demo_hw(struct mod_struct_ops_ctx *ctx)
{
	struct demo_hw_ctx hw_ctx = {
		.ctx = ctx,
	};
	return __bpf_prog_run(hw_prog, &hw_ctx, BPF_DISPATCHER_FUNC(demo_hw));
}

int reg_cmap_ext_demo_ops(struct mod_struct_ops_demo *new_ext_ops, int hw_prog_fd) 
{
	int res = 0;
	if (hw_prog_fd == 0)
		return -1;
	spin_lock(&static_ops_lock);
	if (bpf_ops != NULL) {
		res = -EEXIST;
		goto error;
	}
	if (!bpf_try_module_get(new_ext_ops, new_ext_ops->owner)) {
		pr_err("failed to get bpf module");
		goto error;
	}
	bpf_ops = new_ext_ops;
	/* we have get bpf module now*/
	if (new_ext_ops->hello_world != NULL) {
		//static_call_update(__static_hello_world, new_ext_ops->hello_world);
		struct bpf_prog *__prog; 
		__prog = bpf_prog_get(hw_prog_fd);
		if (IS_ERR_OR_NULL(__prog)) {
			pr_err("failed to get prog from kdata");
			res = -EINVAL;
			goto error_set_default;
		}
		bpf_prog_change_hw(hw_prog, __prog);
		hw_prog = __prog;
		pr_debug("mod_struct_ops_demo update hello world");
	} else {
		pr_err("mod_struct_ops_demo reg not have hello world");
		res = -EINVAL;
		goto error_set_default;
	}
	spin_unlock(&static_ops_lock);
	return 0;

error_set_default:;
	bpf_module_put(new_ext_ops, new_ext_ops->owner);
	bpf_ops = NULL;
	//set_default_static_funcs();
error:
	spin_unlock(&static_ops_lock);
	return res; 
}
EXPORT_SYMBOL(reg_cmap_ext_demo_ops);

void unreg_cmap_ext_demo_ops(struct mod_struct_ops_demo *ops)
{
	spin_lock(&static_ops_lock);
	if (bpf_ops != NULL) {
		bpf_module_put(bpf_ops, bpf_ops->owner);
		bpf_ops = NULL;
		//set_default_static_funcs();
		bpf_prog_change_hw(hw_prog, NULL);
		hw_prog = NULL;
	}
	spin_unlock(&static_ops_lock);
}
EXPORT_SYMBOL(unreg_cmap_ext_demo_ops);

int map_ext_alloc_check(union bpf_attr *attr) 
{
	return attr->value_size == sizeof(struct mod_struct_ops_ctx);
}

static struct bpf_map *map_ext_alloc(union bpf_attr *attr)
{
	struct static_map_ext *ext_map;
	ext_map = bpf_map_area_alloc(sizeof(*ext_map), -1);
	if (!ext_map)
		return ERR_PTR(-ENOMEM);
	memset(&ext_map->ctx, 0, sizeof(ext_map->ctx));
	return (struct bpf_map*)ext_map;
}

static void map_ext_free(struct bpf_map *map) {
	bpf_map_area_free(map);
}

static void* map_ext_lookup_elem(struct bpf_map *map, void *key) 
{
	struct static_map_ext *ext_map = (struct static_map_ext*)map;
	//static_hello_world(&(ext_map->ctx));
	bpf_prog_run_demo_hw(&(ext_map->ctx));
	return &(ext_map->ctx);
}

static long map_ext_update_elem(struct bpf_map *map, void *key, void *value, u64 flags) 
{
	return 0;
}

static long map_ext_delete_elem(struct bpf_map *map, void *key) {
	return 0;
}

static u64 map_ext_mem_usage(const struct bpf_map *map) 
{
	return 4;
}

static struct bpf_map_ops map_ext_ops = {
	.map_alloc = map_ext_alloc,
	.map_free = map_ext_free,
	.map_lookup_elem = map_ext_lookup_elem,
	.map_update_elem = map_ext_update_elem,
	.map_delete_elem = map_ext_delete_elem,
	.map_mem_usage = map_ext_mem_usage
};

static int __init map_ext_cmaps_init(void) {
	pr_info("register static map_ext_cmaps");
	return bpf_register_static_cmap(&map_ext_ops, THIS_MODULE);
}

static void __exit map_ext_cmaps_exit(void) {
	pr_info("unregister static map_ext_cmaps");
	bpf_unregister_static_cmap(THIS_MODULE);
}

/* Register module functions */
module_init(map_ext_cmaps_init);
module_exit(map_ext_cmaps_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chonepieceyb");
MODULE_DESCRIPTION("A simple CMAP with bpf module struct ops extension demo.");
MODULE_VERSION("0.01");
