#include "../common.h"

char _license[] SEC("license") = "GPL";

#define __TARGET_ARCH_x86
#include <bpf/bpf_tracing.h>
#include "../fasthash.h"

#define MAX_ENTRY 65536

#define KEY_RANGE 4096

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

	struct pkt_5tuple_with_pad pkt_with_pad = {0};
	struct value_with_pad value_with_pad = {0};
        
	pkt_with_pad.key = bpf_get_prandom_u32() % KEY_RANGE;
	value_with_pad.data = pkt_with_pad.key;
	// pkt_with_pad.key = 1;
	int res = bpf_map_update_elem(&skip_list, &pkt_with_pad, &value_with_pad, 0);

	if (res < 0) {
		log_error("update: %d, lookup failed", pkt_with_pad.key);
		goto error;
	}

	res = bpf_map_pop_elem(&skip_list, &value_with_pad);
	if (res < 0) {
		log_error("pop: %d, pop failed", pkt_with_pad.key);
		goto error;
	}
	PACKET_COUNT_MAP_UPDATE
finish:
	return XDP_DROP;
error:
	return XDP_DROP;
}