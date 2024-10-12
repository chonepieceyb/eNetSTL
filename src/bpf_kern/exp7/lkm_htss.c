#include "../common.h"

char _license[] SEC("license") = "GPL";

PACKET_COUNT_MAP_DEFINE

#define __TARGET_ARCH_x86
#include <bpf/bpf_tracing.h>

#define MAX_ENTRY 2048

/* core malloc aera */
typedef __u16 sig_t;
typedef __u16 set_t;


struct {
	__uint(type, BPF_MAP_TYPE_STATIC_CUSTOM_MAP);
	__type(key, struct pkt_5tuple);
	__type(value, set_t);
	__uint(max_entries, MAX_ENTRY);
} htss SEC(".maps");

/* test program */
SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
	LATENCY_START_TIMESTAMP_DEFINE

	set_t set_id = 1;

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

	set_t *set_id_res = bpf_map_lookup_elem(&htss, &pkt);

	PACKET_COUNT_MAP_UPDATE
#ifdef LATENCY_EXP
	SWAP_MAC_AND_RETURN_XDP_TX(ctx) 
#endif
finish:
	return XDP_DROP;
}