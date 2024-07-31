#include <linux/static_call.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/math.h>
#include <linux/bpf.h>

#include "empty_scmap_with_callback.h"

extern int bpf_register_static_cmap(struct bpf_map_ops *map,
				    struct module *onwer);
extern void bpf_unregister_static_cmap(struct module *onwer);
extern void bpf_map_area_free(void *area);
extern void *bpf_map_area_alloc(u64 size, int numa_node);

struct empty_scmap_callback_ops *callback_ops;
static DEFINE_SPINLOCK(callback_ops_lock);

#if USE_CALLBACK_PARAM_COUNT == 1
static int default_empty_scmap_callback(u64 param1)
{
	return 0;
}
#elif USE_CALLBACK_PARAM_COUNT == 5
static int default_empty_scmap_callback(u64 param1, u64 param2, u64 param3,
					u64 param4, u64 param5)
{
	return 0;
}
#else
#error "Unsupported USE_CALLBACK_PARAM_COUNT"
#endif
DEFINE_STATIC_CALL_RET0(empty_scmap_callback, default_empty_scmap_callback);

int empty_scmap_callback_register(struct empty_scmap_callback_ops *ops)
{
	int ret = 0;

	if (!ops || !ops->callback || !ops->owner) {
		pr_err("empty_scmap_with_callback: invalid ops or callback or owner\n");
		ret = -EINVAL;
		goto err;
	}

	spin_lock(&callback_ops_lock);

	if (callback_ops) {
		pr_err("empty_scmap_with_callback: callback already registered\n");
		ret = -EEXIST;
		goto err_unlock;
	}
	if (!bpf_try_module_get(ops, ops->owner)) {
		pr_err("empty_scmap_with_callback: failed to get BPF module\n");
		ret = -ENODEV;
		goto err_unlock;
	}
	static_call_update(empty_scmap_callback, ops->callback);
	callback_ops = ops;

err_unlock:
	spin_unlock(&callback_ops_lock);
err:
	return ret;
}
EXPORT_SYMBOL_GPL(empty_scmap_callback_register);

void empty_scmap_callback_unregister(struct empty_scmap_callback_ops *ops)
{
	if (!ops || !ops->owner) {
		pr_warn("empty_scmap_with_callback: invalid ops or owner; ignoring\n");
		return;
	}

	spin_lock(&callback_ops_lock);

	callback_ops = NULL;
	static_call_update(empty_scmap_callback, default_empty_scmap_callback);
	bpf_module_put(ops, ops->owner);

	spin_unlock(&callback_ops_lock);
}
EXPORT_SYMBOL_GPL(empty_scmap_callback_unregister);

struct static_empty_cb_map {
	struct bpf_map map;
};

int empty_cb_alloc_check(union bpf_attr *attr)
{
	return 0;
}

static struct bpf_map *empty_cb_alloc(union bpf_attr *attr)
{
	struct static_empty_cb_map *map;
	map = bpf_map_area_alloc(sizeof(struct static_empty_cb_map),
				 NUMA_NO_NODE);
	if (map == NULL) {
		return ERR_PTR(-ENOMEM);
	}
	return (struct bpf_map *)map;
}

static void empty_cb_free(struct bpf_map *map)
{
	bpf_map_area_free(map);
}

static void *empty_cb_lookup_elem(struct bpf_map *map, void *key)
{
	u64 *args = (u64 *)key;

#if USE_CALLBACK_PARAM_COUNT == 1
	static_call(empty_scmap_callback)(args[0]);
#elif USE_CALLBACK_PARAM_COUNT == 5
	static_call(empty_scmap_callback)(args[0], args[1], args[2], args[3],
					  args[4]);
#else
#error "Unsupported USE_CALLBACK_PARAM_COUNT"
#endif

	return NULL;
}

static long empty_cb_update_elem(struct bpf_map *map, void *key, void *value,
				 u64 flags)
{
	return 0;
}

static long empty_cb_delete_elem(struct bpf_map *map, void *key)
{
	return 0;
}

static u64 empty_cb_mem_usage(const struct bpf_map *map)
{
	return 0;
}

static struct bpf_map_ops empty_cb_ops = {
	.map_alloc = empty_cb_alloc,
	.map_free = empty_cb_free,
	.map_lookup_elem = empty_cb_lookup_elem,
	.map_update_elem = empty_cb_update_elem,
	.map_delete_elem = empty_cb_delete_elem,
	.map_mem_usage = empty_cb_mem_usage
};

static int __init empty_cmaps_with_callback_init(void)
{
	pr_info("register static empty_scmap_with_callback");
	return bpf_register_static_cmap(&empty_cb_ops, THIS_MODULE);
}

static void __exit empty_cmaps_with_callback_exit(void)
{
	pr_info("unregister static empty_scmap_with_callback");
	bpf_unregister_static_cmap(THIS_MODULE);
}

module_init(empty_cmaps_with_callback_init);
module_exit(empty_cmaps_with_callback_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chonepieceyb");
MODULE_DESCRIPTION("An empty scmap with lookup callback");
MODULE_VERSION("0.0.1");
