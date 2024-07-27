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

#define SKETCH_WIDTH 8
#define SKETCH_DEPTH 4
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
	__type(key, struct sketch);
	__type(value, u32);
} sketch_map SEC(".maps");


SEC("xdp") int xdp_main(struct xdp_md *ctx)
{
	//随机采样
	u32 random_number = bpf_get_prandom_u32() % 10;
	if (random_number != 1) {
		return XDP_PASS;
	}

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

	bpf_map_update_elem(&sketch_map, &pkt, &v, BPF_ANY);
out:
	return XDP_PASS;
}


SEC("xdp") int xdp_test(struct xdp_md *ctx)
{
	//随机采样
	u32 random_number = bpf_get_prandom_u32() % 10;
	if (random_number != 1) {
		return XDP_PASS;
	}

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

	bpf_map_update_elem(&sketch_map, &pkt, &v, BPF_ANY);
out:
	return XDP_PASS;
}