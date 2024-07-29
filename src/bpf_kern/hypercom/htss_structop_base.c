/*
 * @author chonepieceyb
 * testing BPF_STRUCT_OP for my st_demo 
 */
#include "../common.h"
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_STATIC_CUSTOM_MAP);
	__type(key, struct pkt_5tuple);
	__type(value, __u32);
	__uint(max_entries, 1);
} htss_struct_op_map SEC(".maps");

SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
	__u32 zero = 0;

	struct pkt_5tuple pkt;
	void *data, *data_end;
	struct hdr_cursor nh;
	int ret;

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	nh.pos = data;
	if (unlikely((ret = parse_pkt_5tuple(&nh, data_end, &pkt)) != 0)) {
		log_error("cannot parse packet: %d", ret);
		goto finish;
	} else {
		log_debug(
			"pkt: src_ip=0x%08x src_port=0x%04x dst_ip=0x%08x dst_port=0x%04x proto=0x%02x",
			pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port,
			pkt.proto);
	}
	int update_res = 0;
	update_res = bpf_map_update_elem(&htss_struct_op_map, &pkt, &zero, BPF_ANY);
	log_debug("update_res: %d", update_res);
	int *res = bpf_map_lookup_elem(&htss_struct_op_map, &pkt);
	if (res) {
			log_debug("found: %d", *res);
			return XDP_DROP;
	}
finish:
	return XDP_DROP;
}