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

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct pkt_count);
	__uint(max_entries, 40);
	__uint(pinning, 1);
} count_map SEC(".maps");

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

	// 性能测试
	u32 cpu_id = bpf_get_smp_processor_id();
	struct pkt_count *current_count = bpf_map_lookup_elem(&count_map, &cpu_id);
	if (current_count == NULL) {
		log_debug("current_count is null");
		goto finish;
	}

	// 在这里修改读写比例，当前为写/读 = 1/32
	int rw_ratio = 2;
	if(current_count->rx_count % rw_ratio == 0) {
		bpf_map_update_elem(&htss_struct_op_map, &pkt, &zero, BPF_ANY);
	} else {
		bpf_map_lookup_elem(&htss_struct_op_map, &pkt);
	}
	// 纯读
	// bpf_map_lookup_elem(&htss_struct_op_map, &pkt);

	current_count->rx_count = current_count->rx_count + 1;
finish:
	return XDP_DROP;
}