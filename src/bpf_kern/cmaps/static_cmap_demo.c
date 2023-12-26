#include "../common.h"

char _license[] SEC("license") = "GPL";

struct cmap_key_type {
	int key;
};

struct cmap_value_type {
    	char data[64];
};

struct {
	__uint(type, BPF_MAP_TYPE_STATIC_CUSTOM_MAP);
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
        val = bpf_map_lookup_elem(&cmap, &key);
        if (val == NULL) {
                log_error("static cmap lookup failed");
                return XDP_DROP;
        }	
        log_info("static cmap: %s", &val->data);
        return XDP_PASS;
}