#include "../common.h"
#include "../sk_common.h"
#include "../sk_config.h"
#include "../bpf_hash_alg_simd.h"
#include "../sk_cm.h"

#include <bpf/bpf_tracing.h>

struct countmin {
	__u32 values[HASHFN_N][COLUMNS];
};

struct hash_mod_struct_ops {
	int (*callback)(struct countmin *ctx, int i, u32 hash);
	struct module *owner;
};

char _license[] SEC("license") = "GPL";

SEC("struct_ops/callback")
int BPF_PROG(hash_callback, struct countmin *cm, int i, u32 hash)
{
	u32 target_idx;

	target_idx = hash & (COLUMNS - 1);
	i &= HASHFN_N - 1;
	NO_TEAR_ADD(cm->values[i][target_idx], 1);

	return 0;
}

SEC(".struct_ops")
struct hash_mod_struct_ops hash_ops = {
	.callback = (void *)hash_callback,
};
