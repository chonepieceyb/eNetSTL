#include "vmlinux.h"

#include "common.h"

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, uint32_t);
	__type(value, struct pkt_5tuple);
} pkt_5tuple_map SEC(".maps");

SEC("xdp") int xdp_main(struct xdp_md *ctx)
{
	struct pkt_5tuple *pkt;
	uint32_t zero = 0;
	void *data, *data_end;
	struct hdr_cursor nh;
	int ret;

	pkt = bpf_map_lookup_elem(&pkt_5tuple_map, &zero);
	if (pkt == NULL) {
		log_error("cannot find pkt_5tuple");
		goto out;
	}

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	nh.pos = data;
	if ((ret = parse_pkt_5tuple(&nh, data_end, pkt)) != 0) {
		log_error("cannot parse packet: %d", ret);
	} else {
		log_debug(
			"pkt: src_ip=0x%08x src_port=0x%04x dst_ip=0x%08x dst_port=0x%04x proto=0x%02x",
			pkt->src_ip, pkt->src_port, pkt->dst_ip, pkt->dst_port,
			pkt->proto);
	}

out:
	return XDP_DROP;
}
