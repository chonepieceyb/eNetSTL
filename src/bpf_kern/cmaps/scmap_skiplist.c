#include "../common.h"

char _license[] SEC("license") = "GPL";

#define __TARGET_ARCH_x86
#include <bpf/bpf_tracing.h>
#include "../fasthash.h"

#define MAX_ENTRY 1024

#define KEY_RANGE 2048

struct pkt_5tuple_with_pad {
	__u8 pad[46];
	// struct pkt_5tuple pkt;
	__u16 key;
} __attribute__((packed));



struct value_with_pad {
	__u8 pad[120];
	__u64 data;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_STATIC_CUSTOM_MAP);
	__type(key, struct pkt_5tuple_with_pad);
	__type(value, struct value_with_pad);
	__uint(max_entries, MAX_ENTRY);
	// __uint(pinning, 1);
} skip_list SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 1);
} init_map SEC(".maps");

static int init = 0;

// /* exp setup program */
// SEC("xdp")
// int add_data(struct xdp_md *ctx)
// {
// 	struct pkt_5tuple pkt = { 0 };
// 	void *data, *data_end;
// 	struct hdr_cursor nh;
// 	int ret;

// 	data = (void *)(long)ctx->data;
// 	data_end = (void *)(long)ctx->data_end;
// 	nh.pos = data;
// 	if (unlikely((ret = parse_pkt_5tuple(&nh, data_end, &pkt)) != 0)) {
// 		log_error("cannot parse packet: %d", ret);
// 		goto finish;
// 	} else {
// 		log_debug(
// 			"pkt: src_ip=0x%08x src_port=0x%04x dst_ip=0x%08x dst_port=0x%04x proto=0x%02x",
// 			pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port,
// 			pkt.proto);
// 	}

// 	__u64 key = (__u64)pkt.dst_port;

// 	int add_res = bpf_map_update_elem(&skip_list, &key, &key, BPF_ANY);
// 	log_debug("dst port: %d, add_res: %d\n", pkt.dst_port, add_res);
// 	if (add_res != 0) {
// 		log_error("add failed\n");
// 	}

// finish:
// 	return XDP_DROP;
// }

// /* exp program */
// SEC("xdp")
// int delete_data(struct xdp_md *ctx)
// {
// 	struct pkt_5tuple pkt = { 0 };
// 	void *data, *data_end;
// 	struct hdr_cursor nh;
// 	int ret;

// 	data = (void *)(long)ctx->data;
// 	data_end = (void *)(long)ctx->data_end;
// 	nh.pos = data;
// 	if (unlikely((ret = parse_pkt_5tuple(&nh, data_end, &pkt)) != 0)) {
// 		log_error("cannot parse packet: %d", ret);
// 		goto finish;
// 	} else {
// 		log_debug(
// 			"pkt: src_ip=0x%08x src_port=0x%04x dst_ip=0x%08x dst_port=0x%04x proto=0x%02x",
// 			pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port,
// 			pkt.proto);
// 	}

// 	__u64 key = (__u64)pkt.dst_port;

// 	if (pkt.dst_port % 2 == 0) {
// 		long delete_res = bpf_map_delete_elem(&skip_list, &key);
// 		log_debug("dst port: %d, delete_res: %d\n", pkt.dst_port,
// 			  delete_res == NULL ? 0 : 1);
// 		if (delete_res != 0) {
// 			log_error("delete failed\n");
// 		}
// 	}

// finish:
// 	return XDP_DROP;
// }

// /* lookup program */
// SEC("xdp")
// int xdp_main(struct xdp_md *ctx)
// {
// 	struct pkt_5tuple pkt = { 0 };
// 	void *data, *data_end;
// 	struct hdr_cursor nh;
// 	int ret;

// 	data = (void *)(long)ctx->data;
// 	data_end = (void *)(long)ctx->data_end;
// 	nh.pos = data;
// 	if (unlikely((ret = parse_pkt_5tuple(&nh, data_end, &pkt)) != 0)) {
// 		log_error("cannot parse packet: %d", ret);
// 		goto finish;
// 	} else {
// 		log_debug(
// 			"pkt: src_ip=0x%08x src_port=0x%04x dst_ip=0x%08x dst_port=0x%04x proto=0x%02x",
// 			pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port,
// 			pkt.proto);
// 	}

// 	__u64 key = (__u64)pkt.dst_port;

// 	struct __u64 *lookup_res = bpf_map_lookup_elem(&skip_list, &key);
// 	log_debug("dst port: %d, lookup_res: %d\n", pkt.dst_port,
// 		  lookup_res == NULL ? 0 : 1);
// finish:
// 	return XDP_DROP;
// }

/* lookup program */
SEC("xdp")
int xdp_test(struct xdp_md *ctx)
{
	struct pkt_5tuple_with_pad pkt_with_pad = {};
	struct value_with_pad value_with_pad = {};

	int zero = 0;
	int *res = bpf_map_lookup_elem(&init_map, &zero);
	if (res == NULL) {
		goto finish;
	}
	if (*res == 0) {
		for (int i = 0; i < KEY_RANGE; i ++) {
			pkt_with_pad.key = i;
			value_with_pad.data = i;
			bpf_map_update_elem(&skip_list, &pkt_with_pad, &value_with_pad, BPF_ANY);
		}
		*res = 1;
	}

	pkt_with_pad.key = bpf_get_prandom_u32() % KEY_RANGE;
	// pkt_with_pad.key = 1;

	struct value_with_pad *lookup_res = bpf_map_lookup_elem(&skip_list, &pkt_with_pad);
	if (lookup_res == NULL) {
		log_error("lookup_key: %d, lookup failed", pkt_with_pad.key);
		goto finish;
	}

	int adjust_res = bpf_xdp_adjust_tail(ctx, 128);
	if (adjust_res != 0) {
		goto finish;
	}
	void *pkt_start = (void*)(long)ctx->data;
	if (pkt_start + sizeof(struct value_with_pad) > ctx->data_end) {
		goto finish;
	}
	__builtin_memcpy(pkt_start, lookup_res, sizeof(struct value_with_pad));

	// __builtin_memcpy(((void *)(long)ctx->data_end - sizeof(struct value_with_pad)), &value_with_pad, sizeof(struct value_with_pad));

	// log_error("lookup_key: %d, lookup_res: %d", pkt_with_pad.pkt.dst_port, *lookup_res);
	// log_error("pkt_start: %d, lookup_res: %d", ((struct value_with_pad *)pkt_start)->data, lookup_res->data);
	if (*(__u64 *)pkt_start == 99999) {
		return XDP_TX;
	}

finish:
	return XDP_DROP;
}

SEC("xdp")
int add_test(struct xdp_md *ctx)
{
	struct pkt_5tuple_with_pad pkt_with_pad = {0};
	struct value_with_pad value_with_pad = {0};

	int zero = 0;
	int *res = bpf_map_lookup_elem(&init_map, &zero);
	if (res == NULL) {
		goto finish;
	}
	if (*res == 0) {
		for (int i = 0; i < KEY_RANGE; i ++) {
			pkt_with_pad.key = i;
			value_with_pad.data = i;
			bpf_map_update_elem(&skip_list, &pkt_with_pad, &value_with_pad, BPF_ANY);
		}
		*res = 1;
	}

	zero = 0;
	struct pkt_5tuple_with_pad pkt_push = {0};
	pkt_push.key = bpf_get_prandom_u32() % KEY_RANGE;

	long pop_res = -2;
	pop_res = bpf_map_push_elem(&skip_list, &pkt_push, zero);
	if (pop_res == NULL) {
		goto finish;
	}
	log_debug("pop_res: %d\n", pop_res);

	__u64 *lookup_res = bpf_map_lookup_elem(&skip_list, &pkt_push);
	log_debug("lookup_res: %d\n", lookup_res == NULL ? 0 : 1);

finish:;
	return XDP_DROP;
}