#include "../common.h"
#include "../bpf_hash_alg_simd.h"

#include <bpf/bpf_tracing.h>

#define test_hash_mod_struct_ops_log(level, fmt, ...)                    \
	log_##level(" test_hash_mod_struct_ops: " fmt " (%s @ line %d)", \
		    ##__VA_ARGS__, __func__, __LINE__)

#define HASH_MOD_STRUCT_OPS_CTX_SIZE 16384
#define TEST_HASH_MOD_STRUCT_OPS_SEEDx8 \
	0x1234, 0x5678, 0x9abc, 0xdef0, 0x1234, 0x5678, 0x9abc, 0xdef0

struct test_hash_mod_struct_ops_ctx {
	u32 val;
	u8 __pad[HASH_MOD_STRUCT_OPS_CTX_SIZE - sizeof(u32)];
} __attribute__((packed));

struct hash_mod_struct_ops {
	int (*callback)(struct test_hash_mod_struct_ops_ctx *ctx, int i,
			u32 hash);
	struct module *owner;
};

char _license[] SEC("license") = "GPL";

SEC("struct_ops/callback")
int BPF_PROG(hash_callback, struct test_hash_mod_struct_ops_ctx *c, int i,
	     u32 hash)
{
	c->val += hash;
	test_hash_mod_struct_ops_log(debug, "c->val = %u, i = %d, hash = %u",
				     c->val, i, hash);
	return 0;
}

SEC(".struct_ops")
struct hash_mod_struct_ops hash_ops = {
	.callback = (void *)hash_callback,
};
