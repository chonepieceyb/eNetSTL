#include "../common.h"
#include "../sk_common.h"
#include "../sk_config.h"
#include "../bpf_hash_alg_simd.h"
#include "../sk_cm.h"

#include <bpf/bpf_tracing.h>

struct countmin_element {
	u32 value;
	u8 __pad[COUNTMIN_ELEMENT_SIZE - sizeof(u32)];
} __attribute__((packed));

struct countmin {
	struct countmin_element elements[HASHFN_N][COLUMNS];
};

struct hash_mod_struct_ops {
	int (*callback)(struct countmin_element *element, int i, u32 hash);
	struct module *owner;
};

char _license[] SEC("license") = "GPL";

SEC("struct_ops/callback")
int BPF_PROG(hash_callback, struct countmin_element *element, int i, u32 hash)
{
	NO_TEAR_ADD(element->value, 1);

	return 0;
}

SEC(".struct_ops")
struct hash_mod_struct_ops hash_ops = {
	.callback = (void *)hash_callback,
};
