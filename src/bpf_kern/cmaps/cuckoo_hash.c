#include "../common.h"

#define CUCKOO_HASH_MAX_ENTRIES 32

char _license[] SEC("license") = "GPL";

struct pkt_5tuple {
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	uint8_t proto;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_STATIC_CUSTOM_MAP);
	__type(key, struct pkt_5tuple);
	__type(value, uint32_t);
	__uint(max_entries, CUCKOO_HASH_MAX_ENTRIES);
} cuckoo_hash_map SEC(".maps");

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	struct pkt_5tuple key = {
		.src_ip = bpf_get_prandom_u32(),
		.dst_ip = bpf_get_prandom_u32(),
		.src_port = bpf_get_prandom_u32(),
		.dst_port = bpf_get_prandom_u32(),
		.proto = bpf_get_prandom_u32(),
	};
	uint32_t value = bpf_get_prandom_u32(), *data;

	xdp_assert_eq(0, bpf_map_update_elem(&cuckoo_hash_map, &key, &value, 0),
		      "cuckoo hash bpf_map_update_elem should succeed");
	xdp_assert_neq(NULL, data = bpf_map_lookup_elem(&cuckoo_hash_map, &key),
		       "cuckoo hash bpf_map_lookup_elem should succeed");
	xdp_assert_eq(
		value, *data,
		"cuckoo hash bpf_map_lookup_elem should return the correct value");

	log_debug("cuckoo hash map test passed\n");

xdp_error:
	return XDP_PASS;
}
