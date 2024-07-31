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

COUNT_MAP;

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	struct cmap_value_type *val;
	struct cmap_key_type key = { .key = 0 };
	struct cmap_value_type value = { .data = 0 };

	val = bpf_map_lookup_elem(&cmap, &key);
	if (val == NULL) {
		log_error("failed to lookup scmap");
		return XDP_DROP;
	}

	log_info("get res %d", val->data);

	COUNT_MAP_INCREMENT;

out:
	return XDP_DROP;
}
