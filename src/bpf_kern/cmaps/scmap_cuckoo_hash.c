#include "../common.h"

#define CUCKOO_HASH_ENTRIES 128

#define cuckoo_log(level, fmt, ...)                                 \
	log_##level(" cuckoo_hash (scmap): " fmt " (%s @ line %d)", \
		    ##__VA_ARGS__, __func__, __LINE__)

char _license[] SEC("license") = "GPL";

struct pkt_5tuple_with_pad {
	struct pkt_5tuple pkt;
	uint8_t __pad[3];
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_STATIC_CUSTOM_MAP);
	__type(key, struct pkt_5tuple_with_pad);
	__type(value, uint32_t);
	__uint(max_entries, CUCKOO_HASH_ENTRIES);
} cuckoo_hash_map SEC(".maps");

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	struct pkt_5tuple_with_pad pkt;
	uint32_t *curr_count, count;
	void *data, *data_end;
	struct hdr_cursor nh;
	int ret;

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	nh.pos = data;
	if ((ret = parse_pkt_5tuple(&nh, data_end, &pkt.pkt)) != 0) {
		cuckoo_log(error, "cannot parse packet: %d", ret);
		goto out;
	} else {
		cuckoo_log(
			debug,
			"pkt: src_ip=0x%08x src_port=0x%04x dst_ip=0x%08x dst_port=0x%04x proto=0x%02x",
			pkt.pkt.src_ip, pkt.pkt.src_port, pkt.pkt.dst_ip,
			pkt.pkt.dst_port, pkt.pkt.proto);
	}

	curr_count = bpf_map_lookup_elem(&cuckoo_hash_map, &pkt);
	if (curr_count != NULL) {
		cuckoo_log(debug, "found packet: %d", *curr_count);
		*curr_count = *curr_count + 1;
		cuckoo_log(debug, "updated packet in place");
		goto out;
	} else {
		cuckoo_log(debug, "cannot find packet: %d", ret);
		count = 1;
	}

	ret = bpf_map_update_elem(&cuckoo_hash_map, &pkt, &count, BPF_ANY);
	if (ret != 0) {
		cuckoo_log(error, "cannot update packet: %d", ret);
		goto out;
	} else {
		cuckoo_log(debug, "updated packet");
	}

out:
	return XDP_DROP;
}
