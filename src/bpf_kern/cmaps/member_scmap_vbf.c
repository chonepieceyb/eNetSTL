#include "../common.h"

char _license[] SEC("license") = "GPL";

#define __TARGET_ARCH_x86
#include <bpf/bpf_tracing.h>

#define MAX_ENTRY 1024

struct {
	__uint(type, BPF_MAP_TYPE_STATIC_CUSTOM_MAP);
	__type(key, struct pkt_5tuple);
	__type(value, int);
	__uint(max_entries, MAX_ENTRY);
	__uint(pinning, 1);
} vbf_cm_map SEC(".maps");

/* exp setup program */
SEC("xdp")
int add_data(struct xdp_md *ctx) {

	struct pkt_5tuple pkt = {0};	
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
			pkt.src_ip, pkt.src_port, pkt.dst_ip,
			pkt.dst_port, pkt.proto);
	}

	__u32 set_id = 1;
	int add_res = bpf_map_update_elem(&vbf_cm_map, &pkt, &set_id, BPF_ANY);
	// int *lookup_res = bpf_map_lookup_elem(&vbf_cm_map, &pkt);
	if (add_res != 0) {
		log_error("add failed\n");
	}

finish:
	return XDP_DROP;
}

/* exp program */
SEC("xdp")
int xdp_main(struct xdp_md *ctx) {

	struct pkt_5tuple pkt = {0};	
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
			pkt.src_ip, pkt.src_port, pkt.dst_ip,
			pkt.dst_port, pkt.proto);
	}

	// int ret = bpf_map_update_elem(&vbf_cm_map, &pkt, &set_id, BPF_ANY);
	int *lookup_res = bpf_map_lookup_elem(&vbf_cm_map, &pkt);
	// bpf_printk("lookup_res: %d\n", lookup_res==NULL ? 0 : 1);
finish:
	return XDP_DROP;
}