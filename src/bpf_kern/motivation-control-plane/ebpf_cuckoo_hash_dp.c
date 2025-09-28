#include "../vmlinux.h"
#include "../common.h"
#include "cuckoo_hash.h"

// Configuration constants for this file
#define CUCKOO_HASH_LOOKUP_ONLY

char LICENSE[] SEC("license") = "GPL";
__u32 dummy;

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

PACKET_COUNT_MAP_DEFINE

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	LATENCY_START_TIMESTAMP_DEFINE

	int zero = 0;
	struct cuckoo_hash_parameters params;
	struct cuckoo_hash *h;
	struct __cuckoo_hash_bfs_queue *bfs_queue;
	struct pkt_5tuple_with_pad pkt = { 0 };
	u32 *curr_count, count;
	void *data, *data_end;
	struct hdr_cursor nh;
	int ret;

	// Get hash table using new API
	h = get_cuckoo_hash(&cuckoo_hash_map);
	if (unlikely(h == NULL)) {
		cuckoo_log(error, "cannot get cuckoo hash");
		goto err;
	}

	// Get BFS queue from map
	bfs_queue = bpf_map_lookup_elem(&__cuckoo_hash_bfs_queue_map, &zero);
	if (unlikely(bfs_queue == NULL)) {
		cuckoo_log(error, "cannot get bfs queue");
		goto err;
	}

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
	}

	ret = cuckoo_hash_lookup_elem(&params, &pkt, &curr_count);
	if (likely(ret == 0)) {
		cuckoo_log(debug, "found packet: %d", *curr_count);
#ifdef CUCKOO_HASH_LOOKUP_ONLY
		cuckoo_log(debug, "lookup only");
		dummy = *curr_count;
#else
		*curr_count = *curr_count + 1;
		cuckoo_log(debug, "updated packet in place");
#endif
		goto out;
	} else {
		cuckoo_log(debug, "cannot find packet: %d", ret);
		count = 1;
	}

#ifdef CUCKOO_HASH_LOOKUP_ONLY
	cuckoo_log(debug, "lookup only");
#else
	ret = cuckoo_hash_update_elem(&params, &pkt, &count);
	if (unlikely(ret != 0)) {
		cuckoo_log(error, "cannot update packet: %d", ret);
		goto err;
	} else {
		cuckoo_log(debug, "updated packet");
	}
#endif

out:

	PACKET_COUNT_MAP_UPDATE

#ifdef LATENCY_EXP
	SWAP_MAC_AND_RETURN_XDP_TX(ctx)
#endif

err:
	return XDP_DROP;
}