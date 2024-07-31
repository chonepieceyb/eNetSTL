#include "../common.h"

char _license[] SEC("license") = "GPL";

#define __TARGET_ARCH_x86
#include <bpf/bpf_tracing.h>
#include "../fasthash.h"

#define MAX_ENTRY 1024

#define HASH_SEED 0xdeadbeef

// 修改这里控制变量
#define KEY_RANGE 4096

struct {
	__uint(type, BPF_MAP_TYPE_STATIC_CUSTOM_MAP);
	__type(key, __u64);
	__type(value, __u64);
	__uint(max_entries, MAX_ENTRY);
	__uint(pinning, 1);
} skip_list SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct pkt_count);
	__uint(max_entries, 40);
	__uint(pinning, 1);
} count_map SEC(".maps");


/* exp setup program */
// SEC("xdp")
// int add_data(struct xdp_md *ctx)
// {

// 	for (__u64 i = 0; i < KEY_RANGE; i ++) {
// 		bpf_map_update_elem(&skip_list, &i, &i, BPF_ANY);
// 	}
// 	log_info("KEY_RANGE: %d, skip_list init finished.\n", KEY_RANGE);
// finish:
// 	return XDP_DROP;
// }

/* exp program */
SEC("xdp")
int delete_data(struct xdp_md *ctx)
{
	struct pkt_5tuple pkt = { 0 };
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

	__u64 key = (__u64)pkt.dst_port;

	if (pkt.dst_port % 2 == 0) {
		long delete_res = bpf_map_delete_elem(&skip_list, &key);
		log_debug("dst port: %d, delete_res: %d\n", pkt.dst_port,
			  delete_res == NULL ? 0 : 1);
		if (delete_res != 0) {
			log_error("delete failed\n");
		}
	}

finish:
	return XDP_DROP;
}

/* lookup program */
SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
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
	// 随机查询KEY_RANGE范围内的key
	__u64 key = bpf_get_prandom_u32() % KEY_RANGE;
	struct __u64 *lookup_res = bpf_map_lookup_elem(&skip_list, &key);

	u32 cpu_id = bpf_get_smp_processor_id();
	struct pkt_count *current_count = bpf_map_lookup_elem(&count_map, &cpu_id);
	if (current_count == NULL) {
		log_debug("current_count is null");
		goto finish;
	}
	current_count->rx_count = current_count->rx_count + 1;
finish:
	return XDP_DROP;
}