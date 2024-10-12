#include "../common.h"

char _license[] SEC("license") = "GPL";

PACKET_COUNT_MAP_DEFINE

#define PER_LONG_BITS_SHIFT 5

#define HBITMAP_LEVEL_1_SHIFT (PER_LONG_BITS_SHIFT)
#define HBITMAP_LEVEL_1 SHIFT_TO_SIZE(HBITMAP_LEVEL_1_SHIFT)

#define HBITMAP_LEVEL_2_SHIFT (PER_LONG_BITS_SHIFT + PER_LONG_BITS_SHIFT)
#define HBITMAP_LEVEL_2 SHIFT_TO_SIZE(HBITMAP_LEVEL_2_SHIFT)

#define HBITMAP_LEVEL_3_SHIFT \
	(PER_LONG_BITS_SHIFT + PER_LONG_BITS_SHIFT + PER_LONG_BITS_SHIFT)
#define HBITMAP_LEVEL_3 SHIFT_TO_SIZE(HBITMAP_LEVEL_3_SHIFT)

#define HBITMAP_LEVEL_4_SHIFT                                              \
	(PER_LONG_BITS_SHIFT + PER_LONG_BITS_SHIFT + PER_LONG_BITS_SHIFT + \
	 PER_LONG_BITS_SHIFT)
#define HBITMAP_LEVEL_4 SHIFT_TO_SIZE(HBITMAP_LEVEL_4_SHIFT)

#define HBITMAP_LEVEL(n) HBITMAP_LEVEL_##n

#define BUCKET_NUM HBITMAP_LEVEL_2
#define BUCKET_NUM_SHIFT HBITMAP_LEVEL_2_SHIFT

struct __packet_type {
	__u64 data;
};

struct __cffs_key_type {
	u32 prio;
};

struct __cffs_value_type {
	struct __packet_type pkt;
};

struct {
	__uint(type, BPF_MAP_TYPE_STATIC_CUSTOM_MAP);
	__type(key, struct __cffs_key_type);
	__type(value, struct __cffs_value_type);
	__uint(max_entries, BUCKET_NUM);
} cffs_piq SEC(".maps");

__u32 h_index_g = 0;

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	LATENCY_START_TIMESTAMP_DEFINE

	int res;
	__u32 prio = 10;
	struct __cffs_key_type key = { .prio = prio };

	struct __cffs_value_type val = { .pkt.data = (__u64)prio };

	res = bpf_map_update_elem(&cffs_piq, &key, &val, 0);
	if (res) {
		goto xdp_error;
	}

	struct __cffs_value_type val_poped;
	res = bpf_map_pop_elem(&cffs_piq, &val_poped);

	PACKET_COUNT_MAP_UPDATE
#ifdef LATENCY_EXP
	SWAP_MAC_AND_RETURN_XDP_TX(ctx) 
#endif
	if (res) {
		goto xdp_error;
	}
	return XDP_DROP;
xdp_error:
	log_error("xdp_error");
	return XDP_DROP;
}