#include "../common.h"

char _license[] SEC("license") = "GPL";

#define __TARGET_ARCH_x86
#include <bpf/bpf_tracing.h>
#include "../fasthash.h"

#define MAX_ENTRY 65536

#define KEY_RANGE (4096 * 2)

struct pkt_5tuple_with_pad {
	__u8 pad[30];
	// struct pkt_5tuple pkt;
	__u16 key;
} __attribute__((packed));

struct value_with_pad {
	__u8 pad[120];
	__u64 data;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_STATIC_CUSTOM_MAP);
	__type(key, struct pkt_5tuple_with_pad);
	__type(value, struct value_with_pad);
	__uint(max_entries, MAX_ENTRY);
	// __uint(pinning, 1);
} skip_list SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 1);
} init_map SEC(".maps");

static int init = 0;

PACKET_COUNT_MAP_DEFINE

/* lookup program */
SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	LATENCY_START_TIMESTAMP_DEFINE

	struct pkt_5tuple_with_pad pkt_with_pad = {};
	struct value_with_pad value_with_pad = {};

	int zero = 0;
	int *res = bpf_map_lookup_elem(&init_map, &zero);
	if (res == NULL) {
		goto error;
	}
	if (*res == 0) {
		for (int i = 0; i < KEY_RANGE; i ++) {
			pkt_with_pad.key = i;
			value_with_pad.data = i;
			bpf_map_update_elem(&skip_list, &pkt_with_pad, &value_with_pad, BPF_ANY);
		}
		*res = 1;
	}

	pkt_with_pad.key = bpf_get_prandom_u32() % KEY_RANGE;
	// pkt_with_pad.key = 1;

	struct value_with_pad *lookup_res = bpf_map_lookup_elem(&skip_list, &pkt_with_pad);
	if (lookup_res == NULL) {
		log_error("lookup_key: %d, lookup failed", pkt_with_pad.key);
		goto error;
	}

	// int adjust_res = bpf_xdp_adjust_tail(ctx, 128);
	// if (adjust_res != 0) {
	// 	goto error;
	// }
	// void *pkt_start = (void*)(long)ctx->data;
	// if (pkt_start + sizeof(struct value_with_pad) > ctx->data_end) {
	// 	goto error;
	// }
	// __builtin_memcpy(pkt_start, lookup_res, sizeof(struct value_with_pad));

	PACKET_COUNT_MAP_UPDATE
#ifdef LATENCY_EXP
	SWAP_MAC_AND_RETURN_XDP_TX(ctx) 
#endif
	return XDP_DROP;
error:;
	return XDP_DROP;
}