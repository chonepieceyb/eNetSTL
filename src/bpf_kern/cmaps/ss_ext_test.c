#include "../common.h"

char _license[] SEC("license") = "GPL";

struct ss_key_type {
        char data [16];
};

struct {
	__uint(type, BPF_MAP_TYPE_STATIC_CUSTOM_MAP);
	__type(key, struct ss_key_type);
	__type(value, u64);  
	__uint(max_entries, 100);
} cmap SEC(".maps");

SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
        u64 val = 1;
        struct ss_key_type key;
        __builtin_memset(&key, 0, sizeof(key));

        int ret = bpf_map_update_elem(&cmap, &key, &val, 0);
        if (ret != 0) {
                log_error("update failed");
        }
        return XDP_DROP;
}