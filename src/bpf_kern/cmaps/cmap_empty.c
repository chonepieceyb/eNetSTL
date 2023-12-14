#include "../common.h"

char _license[] SEC("license") = "GPL";

struct cmap_key_type {
	int key;
};

struct cmap_value_type {
    	int data;
};

struct {
	__uint(type, BPF_MAP_TYPE_CUSTOM_MAP);
	__type(key, struct cmap_key_type);
	__type(value, struct cmap_value_type);  
	__uint(max_entries, 1);
} cmap SEC(".maps");

SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
        struct cmap_value_type *val;
        struct cmap_key_type key = {
                .key = 0
        };
        struct cmap_value_type value = {
                .data = 0
        };
        val = bpf_map_lookup_elem(&cmap, &key);
        bpf_map_update_elem(&cmap, &key, &value, 0);
        bpf_map_delete_elem(&cmap, &key);
        return XDP_DROP;
}