#include "../common.h"

char _license[] SEC("license") = "GPL";

struct cmap_key_type {
	int key;
};

struct cmap_value_type {
	int data;
};

struct {
	__uint(type, BPF_MAP_TYPE_STATIC_CUSTOM_MAP);
	__type(key, struct cmap_key_type);
	__type(value, int);
	__uint(max_entries, 1);
} cmap SEC(".maps");

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	int res;
	struct cmap_key_type key = { .key = 0 };
	struct cmap_value_type value = { .data = 0 };

	if ((res = bpf_map_update_elem(&cmap, &key, &value, BPF_ANY))) {
		log_error("failed to update cmap: %d", res);
		return XDP_DROP;
	}

	return XDP_DROP;
}
