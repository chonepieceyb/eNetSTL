#include "../common.h"

#define STATIC_MAX(a, b) ((a) > (b) ? (a) : (b))

#define USE_CALLBACK_PARAM_COUNT 5

char _license[] SEC("license") = "GPL";

typedef u64 scmap_empty_cb_key_type[STATIC_MAX(USE_CALLBACK_PARAM_COUNT, 1)];

struct {
	__uint(type, BPF_MAP_TYPE_STATIC_CUSTOM_MAP);
	__type(key, scmap_empty_cb_key_type);
	__type(value, int);
	__uint(max_entries, 1);
} scmap_empty_cb SEC(".maps");

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	scmap_empty_cb_key_type key = {
#if USE_CALLBACK_PARAM_COUNT == 0 || USE_CALLBACK_PARAM_COUNT == 1
		1,
#elif USE_CALLBACK_PARAM_COUNT == 5
		1,
		2,
		3,
		4,
		5,
#else
#error "Unsupported USE_CALLBACK_PARAM_COUNT"
#endif
	};
	bpf_map_lookup_elem(&scmap_empty_cb, &key);
	return XDP_DROP;
}
