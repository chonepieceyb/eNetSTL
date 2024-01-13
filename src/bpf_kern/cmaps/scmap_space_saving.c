#include "../vmlinux.h"

#include "../common.h"

#define ss_log(level, fmt, ...)                                      \
	log_##level(" space_saving (scmap): " fmt " (%s @ line %d)", \
		    ##__VA_ARGS__, __func__, __LINE__)

#define inline inline __attribute__((always_inline))

struct pkt_5tuple_with_pad {
	struct pkt_5tuple pkt;
	__u8 pad[3];
} __attribute__((packed));

typedef u16 ss_count_t;

#define SS_NUM_COUNTERS 8

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_STATIC_CUSTOM_MAP);
	__uint(max_entries, SS_NUM_COUNTERS);
	__type(key, struct pkt_5tuple_with_pad);
	__type(value, ss_count_t);
} ss_map SEC(".maps");

SEC("xdp") int xdp_main(struct xdp_md *ctx)
{
	struct hdr_cursor nh;
	void *data_end;
	struct pkt_5tuple_with_pad pkt;
	struct ss *tbl;
	int ret;
	u32 dummy = 0;

	nh.pos = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	ret = parse_pkt_5tuple(&nh, data_end, &pkt.pkt);
	if (unlikely(ret != 0)) {
		ss_log(error, "failed to parse packet 5-tuple: %d", ret);
		goto out;
	} else {
		ss_log(debug,
		       "pkt: src_ip=0x%08x src_port=0x%04x dst_ip=0x%08x dst_port=0x%04x proto=0x%02x",
		       pkt.pkt.src_ip, pkt.pkt.src_port, pkt.pkt.dst_ip,
		       pkt.pkt.dst_port, pkt.pkt.proto);
	}

	ret = bpf_map_update_elem(&ss_map, &pkt, &dummy, BPF_ANY);
	if (unlikely(ret != 0)) {
		ss_log(error, "failed to update space saving table: %d", ret);
		goto out;
	} else {
		ss_log(debug, "successfully updated space saving table");
	}

out:
	return XDP_DROP;
}
