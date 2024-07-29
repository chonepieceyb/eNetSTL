#include "asm-generic/errno-base.h"
#include "linux/stddef.h"
#include <linux/bpf.h>
#include <linux/bpf_custom_map.h>
#include <linux/init.h>
#include <linux/math.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/string.h>
#include "htss_struct_ops.h"

extern int bpf_register_static_cmap(struct bpf_map_ops *map,
                                    struct module *onwer);
extern void bpf_unregister_static_cmap(struct module *onwer);
extern void bpf_map_area_free(void *area);
extern void *bpf_map_area_alloc(u64 size, int numa_node);

struct static_htss_map_structop {
  struct bpf_map map;
  struct htss_struct_ops *ext_ops;
  struct mod_struct_ops_ctx ctx;
};

// static DEFINE_SPINLOCK(ops_mutex);
// static struct htss_struct_ops __rcu *ext_ops = NULL;

struct htss_struct_ops *bpf_ops = NULL;
static DEFINE_SPINLOCK(static_ops_lock);

// stub for eBPF impl
static int htss_loop_up_eBPF(struct mod_struct_ops_ctx *ctx, struct htss_key_type *key) {
  return 0;
}

static int htss_update_eBPF(struct mod_struct_ops_ctx *ctx, struct htss_key_type *key, set_t set_id) {
  return 0;
}

DEFINE_STATIC_CALL_RET0(__htss_loop_up_eBPF, htss_loop_up_eBPF);
DEFINE_STATIC_CALL_RET0(__htss_update_eBPF, htss_update_eBPF);

static int static_htss_loop_up_eBPF(struct mod_struct_ops_ctx *ctx, struct htss_key_type *key) {
  return static_call(__htss_loop_up_eBPF)(ctx, key);
}
static int static_htss_update_eBPF(struct mod_struct_ops_ctx *ctx, struct htss_key_type *key, set_t set_id) {
  return static_call(__htss_update_eBPF)(ctx, key, set_id);
}

void set_default_static_funcs(void) {
  static_call_update(__htss_loop_up_eBPF, htss_loop_up_eBPF);
  static_call_update(__htss_update_eBPF, htss_update_eBPF);
}

int reg_htss_structop_ops(struct htss_struct_ops *new_ext_ops) {
  int res = 0;
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
  if (new_ext_ops->htss_loop_up_eBPF != NULL) {
    static_call_update(__htss_loop_up_eBPF, new_ext_ops->htss_loop_up_eBPF);
    pr_debug("htss_struct_ops update htss_loop_up_eBPF");
  }
  if (new_ext_ops->htss_update_eBPF != NULL) {
	static_call_update(__htss_update_eBPF, new_ext_ops->htss_update_eBPF);
    pr_debug("htss_struct_ops update htss_update_eBPF");
  }
  if(new_ext_ops->htss_loop_up_eBPF == NULL || new_ext_ops->htss_update_eBPF == NULL) {
    pr_err("htss_struct_ops reg not have htss_update_eBPF or htss_loop_up_eBPF");
    res = -EINVAL;
    goto error_set_default;
  }
  spin_unlock(&static_ops_lock);
  return 0;

error_set_default:;
  bpf_module_put(new_ext_ops, new_ext_ops->owner);
  bpf_ops = NULL;
  set_default_static_funcs();
error:
  spin_unlock(&static_ops_lock);
  return res;
}
EXPORT_SYMBOL(reg_htss_structop_ops);

void unreg_htss_structop_ops(struct htss_struct_ops *ops) {
  spin_lock(&static_ops_lock);
  if (bpf_ops != NULL) {
    bpf_module_put(bpf_ops, bpf_ops->owner);
    bpf_ops = NULL;
    set_default_static_funcs();
  }
  spin_unlock(&static_ops_lock);
}
EXPORT_SYMBOL(unreg_htss_structop_ops);

int htss_structop_alloc_check(union bpf_attr *attr) {
  return attr->value_size == sizeof(struct mod_struct_ops_ctx);
}

static struct bpf_map *htss_structop_alloc(union bpf_attr *attr) {
  struct static_htss_map_structop *htss_map;
  htss_map = bpf_map_area_alloc(sizeof(*htss_map), -1);
  if (!htss_map)
    return ERR_PTR(-ENOMEM);

  memset(&htss_map->ctx, 0, sizeof(struct mod_struct_ops_ctx));
  rwlock_init(&htss_map->ctx.rw_lock);
  return (struct bpf_map *)htss_map;
}

static void htss_structop_free(struct bpf_map *map) {
  struct static_htss_map_structop *htss_map;
  if (map == NULL) {
    return;
  }
  htss_map = container_of(map, struct static_htss_map_structop, map);

  bpf_map_area_free(htss_map);
  return;
}

static void *htss_structop_lookup_elem(struct bpf_map *map, void *key) {
  struct static_htss_map_structop *htss_map =
      container_of(map, struct static_htss_map_structop, map);

  __u32 prim_bucket, sec_bucket;
  sig_t tmp_sig;

  // add read lock
  read_lock(&htss_map->ctx.rw_lock);
  // set lookup params

  htss_map->ctx.res = static_htss_loop_up_eBPF(&htss_map->ctx, key);

  read_unlock(&htss_map->ctx.rw_lock);
  return &(htss_map->ctx.res);
}

static long htss_structop_update_elem(struct bpf_map *map, void *key,
                                      void *value, u64 flags) {
  struct static_htss_map_structop *htss_map =
      container_of(map, struct static_htss_map_structop, map);

  long ret = 0;
  set_t flag_mask = 1U << (sizeof(set_t) * 8 - 1);
  __u32 set_id = *(__u32 *)value;

  if ((set_id & flag_mask) != 0) {
    return -1;
  }
  // add writer lock
  write_lock(&htss_map->ctx.rw_lock);

  ret = static_htss_update_eBPF(&htss_map->ctx, key, set_id);

  write_unlock(&htss_map->ctx.rw_lock);
  return ret;
}

static long htss_structop_delete_elem(struct bpf_map *map, void *key) {
  return 0;
}

static u64 htss_structop_mem_usage(const struct bpf_map *map) {
  return sizeof(struct mod_struct_ops_ctx) * num_possible_cpus();
}

static struct bpf_map_ops htss_structop_ops = {
    .map_alloc = htss_structop_alloc,
    .map_free = htss_structop_free,
    .map_lookup_elem = htss_structop_lookup_elem,
    .map_update_elem = htss_structop_update_elem,
    .map_delete_elem = htss_structop_delete_elem,
    .map_mem_usage = htss_structop_mem_usage};

static int __init map_ext_cmaps_init(void) {
  pr_info("register static map_ext_cmaps");
  return bpf_register_static_cmap(&htss_structop_ops, THIS_MODULE);
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
