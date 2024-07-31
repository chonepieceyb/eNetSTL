//程建涛 20230131
//eBPF实现数据结构count-min sketch
#include "../common.h"

#define inline inline __attribute__((always_inline))

#define HASH_SEED_1 0xdeadbeef
#define HASH_SEED_2 0xaaaabbbb

struct pkt_5tuple_with_pad {
	struct pkt_5tuple pkt;
	__u8 pad[3];
} __attribute__((packed));
typedef struct pkt_5tuple_with_pad sketch_key;

#define SKETCH_DEPTH 8
#define SKETCH_WIDTH 256
#define SKETCH_KEY_SIZE sizeof(sketch_key)
#define BLOOMSIZE 32
struct sketch {
	u32 flag;
	u32 bloomMax;
	u32 bloomMin;
	u32 bloomCounts[BLOOMSIZE];
	//Heavy Keeper部分 20240722
	u32 keys[SKETCH_WIDTH * SKETCH_DEPTH];
	sketch_key flows[SKETCH_WIDTH * SKETCH_DEPTH];
};

char _license[] SEC("license") = "GPL";
struct {
	__uint(type, BPF_MAP_TYPE_STATIC_CUSTOM_MAP);
	__uint(max_entries, 1);
	__type(key, sketch_key);
	__type(value, u32);
} sketch_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct pkt_count);
	__uint(max_entries, 40);
	__uint(pinning, 1);
} count_map SEC(".maps");

SEC("xdp") int xdp_main(struct xdp_md *ctx)
{
	struct hdr_cursor nh;
	void *data_end;
	struct pkt_5tuple_with_pad pkt;
	struct sketch *tbl;
	u32 ret;
	u32 v = 0;

	nh.pos = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	ret = parse_pkt_5tuple(&nh, data_end, &pkt.pkt);
	if (unlikely(ret != 0)) {
		log_error("failed to parse packet 5-tuple: %u", ret);
		goto out;
	} else {
		log_debug(
			"pkt: src_ip=0x%08x src_port=0x%04x dst_ip=0x%08x dst_port=0x%04x proto=0x%02x",
			pkt.pkt.src_ip, pkt.pkt.src_port, pkt.pkt.dst_ip,
			pkt.pkt.dst_port, pkt.pkt.proto);
	}

	u32 cpu_id = bpf_get_smp_processor_id();
	struct pkt_count *current_count = bpf_map_lookup_elem(&count_map, &cpu_id);
	if (current_count == NULL) {
		log_debug("current_count is null");
		goto out;
	}
	current_count->rx_count = current_count->rx_count + 1;

	bpf_map_update_elem(&sketch_map, &pkt, &v, BPF_ANY);
	// bpf_map_lookup_elem(&sketch_map, &pkt);

out:
	return XDP_DROP;
}


SEC("xdp") int xdp_test(struct xdp_md *ctx)
{
	//随机采样
	u32 random_number = bpf_get_prandom_u32() % 10;

	struct hdr_cursor nh;
	void *data_end;
	struct pkt_5tuple_with_pad pkt;
	struct sketch *tbl;
	u32 ret;
	u32 v = 0;

	pkt.pkt.src_ip = random_number;
	pkt.pkt.dst_ip = 0x05060708;
	pkt.pkt.src_port = 0x1111;
	pkt.pkt.dst_port = 0x2222;
	pkt.pkt.proto = 0x06;
	pkt.pad[0] = 0;
	pkt.pad[1] = 0;
	pkt.pad[2] = 0;

	for(int i=0;i<10;i++){
		pkt.pkt.src_ip = i;
		bpf_map_update_elem(&sketch_map, &pkt, &v, BPF_ANY);
	}
out:
	return XDP_DROP;
}