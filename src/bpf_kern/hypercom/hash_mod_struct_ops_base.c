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

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct test_hash_mod_struct_ops_ctx);
	__uint(max_entries, 1);
} test_hash_mod_struct_ops_ctx SEC(".maps");

struct hash_mod_struct_ops {
	int (*callback)(struct test_hash_mod_struct_ops_ctx *ctx, int i,
			u32 hash);
	struct module *owner;
};

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	struct pkt_5tuple pkt;
	u32 seeds[8] = { TEST_HASH_MOD_STRUCT_OPS_SEEDx8 };
	struct hdr_cursor nh = {
		.pos = (void *)(long)ctx->data,
	};
	void *data_end = (void *)(long)ctx->data_end;
	struct test_hash_mod_struct_ops_ctx *c;
	int ret, i, zero = 0;

	if ((c = bpf_map_lookup_elem(&test_hash_mod_struct_ops_ctx, &zero)) ==
	    NULL) {
		test_hash_mod_struct_ops_log(error,
					     "bpf_map_lookup_elem() failed");
		goto out;
	}

	c->val = 10;

	if ((ret = parse_pkt_5tuple(&nh, data_end, &pkt)) != 0) {
		test_hash_mod_struct_ops_log(
			error, "parse_pkt_5tuple() failed: %d", ret);
		goto out;
	}

	bpf_fasthash32_alt_avx2_pkt5_with_callback(&pkt, seeds, (u8 *)c);
	test_hash_mod_struct_ops_log(info, "c->val = %u", c->val);

out:
	return XDP_PASS;
}
