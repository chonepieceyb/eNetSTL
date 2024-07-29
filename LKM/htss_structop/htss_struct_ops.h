#ifndef HTSS_STRUCT_OPS_H
#define HTSS_STRUCT_OPS_H

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

struct pkt_5tuple {
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	uint8_t proto;
} __attribute__((packed));

struct htss_key_type {
	char data[13];
};
struct mod_struct_ops_ctx {
  // lookup res
  int res;
  rwlock_t rw_lock;
};

struct htss_struct_ops {
  int (*htss_loop_up_eBPF)(struct mod_struct_ops_ctx *ctx, struct htss_key_type *key);
  int (*htss_update_eBPF)(struct mod_struct_ops_ctx *ctx, struct htss_key_type *key, set_t set_id);
  struct module *owner;
};

#endif
