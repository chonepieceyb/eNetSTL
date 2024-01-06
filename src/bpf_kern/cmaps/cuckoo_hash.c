#include "../common.h"

#define CUCKOO_HASH_MAX_ENTRIES 512
#define CUCKOO_HASH_SIMD

#define ENOSPC 28 /* No space left on device */

char _license[] SEC("license") = "GPL";

struct pkt_5tuple {
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	uint8_t proto;
#ifdef CUCKOO_HASH_SIMD
	/* make this structure 16 bytes to use __cuckoo_hash_k16_cmp_eq */
	uint8_t __pad[3];
#endif
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
	uint32_t r1 = bpf_get_prandom_u32(), r2 = bpf_get_prandom_u32();

	struct pkt_5tuple key = {
		.src_ip = r1,
		.dst_ip = r1,
		.src_port = r1,
		.dst_port = r1,
		.proto = 0x04,
	};
	uint32_t value = r2, *data;
	int ret;

	ret = bpf_map_update_elem(&cuckoo_hash_map, &key, &value, BPF_ANY);
	if (ret == -ENOSPC) {
		log_debug("cuckoo hash map has run out of space\n");
		goto xdp_error;
	}
	xdp_assert_eq(0, ret, "cuckoo hash bpf_map_update_elem should succeed");

	data = bpf_map_lookup_elem(&cuckoo_hash_map, &key);
	xdp_assert_neq(NULL, data,
		       "cuckoo hash bpf_map_lookup_elem should succeed");
	xdp_assert_eq(
		value, *data,
		"cuckoo hash bpf_map_lookup_elem should return the correct value");

	log_debug("cuckoo hash map test passed\n");

xdp_error:
	return XDP_DROP;
}
