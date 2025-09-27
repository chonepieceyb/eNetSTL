#include "../vmlinux.h"
#include "../common.h"
#include "cuckoo_hash.h"

// Configuration constants for this file
#define CUCKOO_HASH_LOOKUP_ONLY

char LICENSE[] SEC("license") = "GPL";

// BPF map definitions
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct cuckoo_hash);
} cuckoo_hash_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct __cuckoo_hash_bfs_queue);
} __cuckoo_hash_bfs_queue_map SEC(".maps");


u32 lookup_value = 0;
u32 update_value = 0;
struct pkt_5tuple_with_pad update_pkt_key = {0};

PACKET_COUNT_MAP_DEFINE

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	int zero = 0;
	struct cuckoo_hash_parameters params;
	struct cuckoo_hash *h;
	struct __cuckoo_hash_bfs_queue *bfs_queue;
	struct pkt_5tuple_with_pad pkt = { 0 };
	u32 *value;
	void *data, *data_end;
	struct hdr_cursor nh;
	int ret;

	cuckoo_log(debug, "xdp_main: starting packet processing");

	// Get hash table using new API
	h = get_cuckoo_hash(&cuckoo_hash_map);
	if (unlikely(h == NULL)) {
		cuckoo_log(error, "cannot get cuckoo hash");
		goto err;
	}
	cuckoo_log(debug, "xdp_main: got hash table at %p, initialized=%d", h, h->initialized);

	// Get BFS queue from map
	bfs_queue = bpf_map_lookup_elem(&__cuckoo_hash_bfs_queue_map, &zero);
	if (unlikely(bfs_queue == NULL)) {
		cuckoo_log(error, "cannot get bfs queue");
		goto err;
	}
	cuckoo_log(debug, "xdp_main: got bfs queue at %p", bfs_queue);

	// Set up parameters
	params.hash_table = h;
	params.bfs_queue = bfs_queue;

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	nh.pos = data;
	if (unlikely((ret = parse_pkt_5tuple(&nh, data_end, &pkt.pkt)) != 0)) {
		cuckoo_log(error, "cannot parse packet: %d", ret);
		goto err;
	} else {
		cuckoo_log(
			debug,
			"pkt: src_ip=0x%08x src_port=0x%04x dst_ip=0x%08x dst_port=0x%04x proto=0x%02x",
			pkt.pkt.src_ip, pkt.pkt.src_port, pkt.pkt.dst_ip,
			pkt.pkt.dst_port, pkt.pkt.proto);
		cuckoo_log(debug, "xdp_main: parsed packet key: 0x%08x...", *((u32*)&pkt));
	}

	ret = cuckoo_hash_lookup_elem(&params, &pkt, &value);
	cuckoo_log(debug, "lookup attempt: src_ip=0x%08x src_port=0x%04x dst_ip=0x%08x dst_port=0x%04x proto=0x%02x, ret=%d",
		pkt.pkt.src_ip, pkt.pkt.src_port, pkt.pkt.dst_ip, pkt.pkt.dst_port, pkt.pkt.proto, ret);
	if (likely(ret == 0)) {
		cuckoo_log(debug, "found packet: %d", *value);
		if (lookup_value != 0 && *value != lookup_value) {
			cuckoo_log(error, "lookup value mismatch: expected %d, got %d", lookup_value, *value);
			goto err;
		}
		cuckoo_log(debug, "xdp_main: lookup successful, value=%d", *value);
	} else {
		cuckoo_log(debug, "cannot find packet: %d", ret);
		cuckoo_log(debug, "xdp_main: lookup failed with ret=%d", ret);
		goto err;
	}

	ret = cuckoo_hash_update_elem(&params, &update_pkt_key, &update_value);
	if (unlikely(ret != 0)) {
		cuckoo_log(error, "cannot update packet: %d", ret);
		goto err;
	} else {
		cuckoo_log(debug, "updated packet");
	}
out:
	return XDP_PASS;

err:
	cuckoo_log(debug, "xdp_main: error path, dropping packet");
	return XDP_DROP;
}