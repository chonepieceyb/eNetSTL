#ifndef MOD_STRUCT_OPS_DEMO_H
#define MOD_STRUCT_OPS_DEMO_H

#include <linux/module.h>

/* static vars */
#define MAX_ENTRY 2048
#define HASH_SEED_1 0xdeadbeef
#define HASH_SEED_2 0xaaaabbbb
#define MEMBER_NO_MATCH 0
#define MEMBER_MAX_PUSHES 8

/* datastruct params */
#define NUM_ENTRIES 1024
#define NUM_BUCKETS 128
#define SIZE_BUCKET_T 32
#define BUCKET_MASK 127
#define MEMBER_BUCKET_ENTRIES 8

typedef __u16 sig_t;
typedef __u16 set_t;
struct member_ht_bucket {
  sig_t sigs[MEMBER_BUCKET_ENTRIES];
  set_t sets[MEMBER_BUCKET_ENTRIES];
};

struct mod_struct_ops_ctx {
  struct member_ht_bucket buckets[NUM_BUCKETS];
  rwlock_t rw_lock;
};

struct mod_struct_ops_demo {
  int (*htss_loop_up_eBPF)(struct mod_struct_ops_ctx *ctx);
  int (*htss_update_eBPF)(struct mod_struct_ops_ctx *ctx);
  struct module *owner;
};

#endif
