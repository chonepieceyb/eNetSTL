#include "vmlinux.h"

#include "common.h"
#include "sk_common.h"
#include "sk_config.h"
#include "sk_cm.h"
#include "fasthash.h"

#define M 0x880355f21e6d1965ULL

_Static_assert((COLUMNS & (COLUMNS - 1)) == 0,
	       "COLUMNS must be a power of two");

static __u32 seeds[] = {
	0xec5853,  0xec5859,  0xec5861,	 0xec587f,  0xec58a7,  0xec58b3,
	0xec58c7,  0xec58d1,  0xec58531, 0xec58592, 0xec58613, 0xec587f4,
	0xec58a75, 0xec58b36, 0xec58c77, 0xec58d18, 0xec58539, 0xec58510,
	0xec58611, 0xec58712, 0xec58a13, 0xec58b14, 0xec58c15, 0xec58d16,
	0xec58521, 0xec58522, 0xec58623, 0xec58724, 0xec58a25, 0xec58b26,
	0xec58c27, 0xec58d28, 0xec58541, 0xec58542, 0xec58643, 0xec58744,
	0xec58a45, 0xec58b46, 0xec58c47, 0xec58d48, 0xec58551, 0xec58552,
	0xec58653, 0xec58754, 0xec58a55, 0xec58b56, 0xec58c57, 0xec58d58,
	0xec58561, 0xec58563, 0xec58663, 0xec58764, 0xec58a65, 0xec58b66,
	0xec58c67, 0xec58d68, 0xec58571, 0xec58572, 0xec58673, 0xec58774,
	0xec58a75, 0xec58b76, 0xec58c77, 0xec58d78,
};

char _license[] SEC("license") = "GPL";

struct countmin_element {
	u32 value;
	u32 key;
} __attribute__((packed));

struct countmin {
	struct countmin_element elements[HASHFN_N][COLUMNS];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct countmin);
	__uint(max_entries, 1);
} countmin SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct pkt_count);
	__uint(max_entries, 40);
	__uint(pinning, 1);
} count_map SEC(".maps");

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

static void __always_inline heavy_keeper_add(struct countmin *cm, void *data,
					     __u64 len)
{
	u32 hash, i = 0, target_idx;
	struct countmin_element *element;

	for (i = 0; i < HASHFN_N; i++) {
		hash = fasthash32(data, len, seeds[i]);
		target_idx = hash & (COLUMNS - 1);
		element = &cm->elements[i][target_idx];

		if (element->key == hash) {
			element->value++;
		} else {
			if (element->value > 0 && prob_action(element->value)) {
				element->key = hash;
				element->value = 1;
			}
		}
	}
}

SEC("xdp") int xdp_main(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };
	struct pkt_5tuple pkt;
	uint32_t zero = 0;
	struct countmin *cm;
	int ret = 0;

	if ((ret = parse_pkt_5tuple(&nh, data_end, &pkt)) != 0) {
		log_error(" failed to parse packet: %d", ret);
		goto out;
	}

	cm = bpf_map_lookup_elem(&countmin, &zero);
	if (!cm) {
		log_error(" invalid entry in the countmin sketch");
		goto out;
	}


	u32 cpu_id = bpf_get_smp_processor_id();
	struct pkt_count *current_count = bpf_map_lookup_elem(&count_map, &cpu_id);
	if (current_count == NULL) {
		log_debug("current_count is null");
		goto out;
	}
	current_count->rx_count = current_count->rx_count + 1;


	heavy_keeper_add(cm, &pkt, sizeof(pkt));
out:
	return XDP_DROP;
}
