#include "../common.h"
#include "../sk_common.h"
#include "../sk_config.h"
#include "../bpf_hash_alg_simd.h"
#include "../sk_cm.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

struct countmin_element {
	u32 value;
	u32 key;
} __attribute__((packed));

struct countmin {
	struct countmin_element elements[HASHFN_N][COLUMNS];
};

struct hash_mod_struct_ops {
	int (*callback)(struct countmin_element *element, int i, u32 hash);
	struct module *owner;
};

char _license[] SEC("license") = "GPL";

/* 实现指数下降的概率；返回 1 代表成功 */
static inline int prob_action(u32 count)
{
	/* 随机采样 */
	u32 random_number =
		bpf_get_prandom_u32() % 100000; /* FIXME: performance penalty */
	if (count < 11) {
		if (random_number < 96336 - 5312 * count)
			return 1;
	} else if (count < 21) {
		if (random_number < 69284 - 2463 * count)
			return 1;
	} else if (count < 31) {
		if (random_number < 43533 - 1142 * count)
			return 1;
	} else if (count < 41) {
		if (random_number < 25472 - 529 * count)
			return 1;
	} else if (count < 51) {
		if (random_number < 14261 - 245 * count)
			return 1;
	} else if (count < 61) {
		if (random_number < 7748 - 114 * count)
			return 1;
	} else if (count < 71) {
		if (random_number < 4119 - 53 * count)
			return 1;
	} else if (count < 81) {
		if (random_number < 2154 - 24 * count)
			return 1;
	} else if (count < 91) {
		if (random_number < 1112 - 11 * count)
			return 1;
	} else if (count < 101) {
		if (random_number < 568 - 5 * count)
			return 1;
	} else {
		if (random_number < 1)
			return 1;
	}

	return 0;
}

SEC("struct_ops/callback")
int BPF_PROG(hash_callback, struct countmin_element *element, int i, u32 hash)
{
	if (element->key == hash) {
		NO_TEAR_ADD(element->value, 1);
	} else {
		if (element->value > 0 && prob_action(element->value)) {
			element->key = hash;
			element->value = 1;
		}
	}

	return 0;
}

SEC(".struct_ops")
struct hash_mod_struct_ops hash_ops = {
	.callback = (void *)hash_callback,
};
