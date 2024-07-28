/*
 * @author chonepieceyb
 * testing BPF_STRUCT_OP for my st_demo 
 */
#include "../common.h"
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";


/*XDP*/
struct ext_map_key_type {
	int key;
};

struct ext_map_value_type {
    	int val;
};

struct {
	__uint(type, BPF_MAP_TYPE_STATIC_CUSTOM_MAP);
	__type(key, struct ext_map_key_type);
	__type(value, struct ext_map_value_type);  
	__uint(max_entries, 1);
} ext_map SEC(".maps");

SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
        struct ext_map_value_type *val;
        struct ext_map_key_type key = {
                .key = 0
        };
        val = bpf_map_lookup_elem(&ext_map, &key);
        if (val == NULL) {
                log_error("cmap lookup failed");
                return XDP_DROP;
        }	
        log_info("ext_map_lookup res %s", &val->val);
        return XDP_PASS;
}