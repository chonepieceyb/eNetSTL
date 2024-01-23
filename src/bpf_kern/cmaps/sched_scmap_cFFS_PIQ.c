#include "../common.h"

char _license[] SEC("license") = "GPL";

#define PER_LONG_BITS_SHIFT 5

#define HBITMAP_LEVEL_1_SHIFT (PER_LONG_BITS_SHIFT)
#define HBITMAP_LEVEL_1 SHIFT_TO_SIZE(HBITMAP_LEVEL_1_SHIFT)

#define HBITMAP_LEVEL_2_SHIFT (PER_LONG_BITS_SHIFT + PER_LONG_BITS_SHIFT)
#define HBITMAP_LEVEL_2 SHIFT_TO_SIZE(HBITMAP_LEVEL_2_SHIFT)

#define HBITMAP_LEVEL_3_SHIFT (PER_LONG_BITS_SHIFT + PER_LONG_BITS_SHIFT + PER_LONG_BITS_SHIFT)
#define HBITMAP_LEVEL_3 SHIFT_TO_SIZE(HBITMAP_LEVEL_3_SHIFT)

#define HBITMAP_LEVEL_4_SHIFT (PER_LONG_BITS_SHIFT + PER_LONG_BITS_SHIFT + PER_LONG_BITS_SHIFT + PER_LONG_BITS_SHIFT)
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
int test_cffs(struct xdp_md *ctx) {
        int res;
        //enquene
        __u32 prio1 = bpf_get_prandom_u32() % (2 * BUCKET_NUM) + h_index_g;
        __u32 prio2 = bpf_get_prandom_u32() % (2 * BUCKET_NUM) + h_index_g;

        __u32 min_prio = min(prio1, prio2);
        __u32 max_prio = max(prio1, prio2);

        log_debug("prio1: %u", prio1);
        log_debug("prio2: %u", prio2);

        struct __cffs_key_type key1 = {
                .prio = prio1
        };
        struct __cffs_key_type key2 = {
                .prio = prio2
        };

        struct __cffs_value_type val1 = {
                .pkt.data = (__u64)prio1
        };
        struct __cffs_value_type val2 = {
                .pkt.data = (__u64)prio2
        };

        res = bpf_map_update_elem(&cffs_piq, &key1, &val1, 0);
        xdp_assert_eq(0, res, "scmap cffs update failed");

        res = bpf_map_update_elem(&cffs_piq, &key2, &val2, 0);
        xdp_assert_eq(0, res, "scmap cffs update2 failed");

        struct __cffs_value_type val1_poped;
        struct __cffs_value_type val2_poped;

        res = bpf_map_pop_elem(&cffs_piq, &val1_poped);
        xdp_assert_eq(0, res, "scmap cffs pop1 failed");

        res = bpf_map_pop_elem(&cffs_piq, &val2_poped);
        xdp_assert_eq(0, res, "scmap cffs pop2 failed");

        log_debug("pop1 pkt data %lu", val1_poped.pkt.data);
        log_debug("pop2 pkt data %lu", val2_poped.pkt.data);
        xdp_assert_eq(min_prio, val1_poped.pkt.data, "pop1 not the pkt with min prio");
        xdp_assert_eq(max_prio, val2_poped.pkt.data, "pop2 not the pkt with max prio");
        log_info("test success");

        if (max_prio > h_index_g + BUCKET_NUM) {
                //should switch
                h_index_g += BUCKET_NUM;
        }

        return XDP_PASS;
xdp_error:
        return XDP_DROP;        
}

SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
        int res;
        __u32 prio = 10;
        struct __cffs_key_type key = {
                .prio = prio
        };

        struct __cffs_value_type val = {
                .pkt.data = (__u64)prio
        };

        res = bpf_map_update_elem(&cffs_piq, &key, &val, 0);
        if (res) {
                goto xdp_error;
        }

        struct __cffs_value_type val_poped;
        res = bpf_map_pop_elem(&cffs_piq, &val_poped);
        if (res) {
                goto xdp_error;
        }
        return XDP_DROP;
xdp_error:
        log_error("xdp_error");
        return XDP_DROP;        
}