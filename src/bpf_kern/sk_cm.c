#include "vmlinux.h"

#include "common.h"
#include "sk_common.h"
#include "fasthash.h"
#include <bpf/bpf_endian.h>
#include "fasthash.h"
#include "xxhash.h"
#include "sk_config.h"

// #define SK_CM_EMPTY_HASH

_Static_assert((COLUMNS & (COLUMNS - 1)) == 0,
	       "COLUMNS must be a power of two");

const static __u32 seeds[] = {
	0xec5853,  0xec5859,  0xec5861,	 0xec587f,  0xec58a7,  0xec58b3,
	0xec58c7,  0xec58d1,  0xec58531, 0xec58592, 0xec58613, 0xec587f4,
	0xec58a75, 0xec58b36, 0xec58c77, 0xec58d18, 0xec58539, 0xec58510,
	0xec58611, 0xec58712, 0xec58a13, 0xec58b14, 0xec58c15, 0xec58d16,
	0xec58521, 0xec58522, 0xec58623, 0xec58724, 0xec58a25, 0xec58b26,
	0xec58c27, 0xec58d28, 0xec58541, 0xec58542, 0xec58643, 0xec58744,
	0xec58a45, 0xec58b46, 0xec58c47, 0xec58d48, 0xec58551, 0xec58552,
	0xec58653, 0xec58754, 0xec58a55, 0xec58b56, 0xec58c57, 0xec58d58,
	0xec58561, 0xec58563, 0xec58663, 0xec58764, 0xec58a65, 0xec58b66,
	0xec58c67, 0xec58d68, 0xec58571, 0xec58572, 0xec58673, 0xec58774,
	0xec58a75, 0xec58b76, 0xec58c77, 0xec58d78,
};

char _license[] SEC("license") = "GPL";

struct countmin {
	__u32 values[HASHFN_N][COLUMNS];
};

#if RECORD
struct pkt_md {
#if _COUNT_PACKETS == 1
	uint64_t drop_cnt;
#endif
#if _COUNT_BYTES == 1
	uint64_t bytes_cnt;
#endif
};
#endif

#if RECORD
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct pkt_md);
	__uint(max_entries, 1);
} dropcnt SEC(".maps");
#endif

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct countmin);
	__uint(max_entries, 1);
} countmin SEC(".maps");

static void __always_inline countmin_add(struct countmin *cm, void *element,
					 __u64 len)
{
	/*
	uint16_t hashes[8];

    	_Static_assert(ARRAY_SIZE(hashes) == HASHFN_N, "Missing hash function");

    	for (int i = 0; i < ARRAY_SIZE(hashes); i++) {
		hashes[i] = (uint16_t)fasthash64(element, len, seeds[i]);
		__u32 target_idx = hashes[i] & (COLUMNS - 1);
		NO_TEAR_ADD(cm->values[i][target_idx], 1);
	}
	return;
*/
	/* Calculate just a single hash and re-use it to update and query the sketch */

	for (int i = 0; i < HASHFN_N; i++) {
#ifdef SK_CM_EMPTY_HASH
		__u32 hash = ((const __u32 *)element)[(len >> 2) - 1] ^
			     seeds[i];
#else
#if USE_XXHASH == 1
		__u32 hash = xxh32(element, len, seeds[i]);
#else
		__u32 hash = fasthash32(element, len, seeds[i]);
#endif
#endif
		__u32 target_idx = hash & (COLUMNS - 1);
		NO_TEAR_ADD(cm->values[i][target_idx], 1);
	}
	return;
}

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	uint64_t nh_off = 0;
	struct eth_hdr *eth = data;
	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		goto DROP;

	uint16_t h_proto = eth->proto;

// parse double vlans
#pragma unroll
	for (int i = 0; i < 2; i++) {
		if (h_proto == bpf_htons(ETH_P_8021Q) ||
		    h_proto == bpf_htons(ETH_P_8021AD)) {
			struct vlan_hdr *vhdr;
			vhdr = data + nh_off;
			nh_off += sizeof(struct vlan_hdr);
			if (data + nh_off > data_end)
				goto DROP;
			h_proto = vhdr->h_vlan_encapsulated_proto;
		}
	}

	switch (h_proto) {
	case bpf_htons(ETH_P_IP):
		break;
	default:
		return XDP_PASS;
	}

	struct pkt_5tuple pkt;

	struct iphdr *ip = data + nh_off;
	if ((void *)&ip[1] > data_end)
		goto DROP;

	pkt.src_ip = ip->saddr;
	pkt.dst_ip = ip->daddr;
	pkt.proto = ip->protocol;

	switch (ip->protocol) {
	case IPPROTO_TCP: {
		struct tcp_hdr *tcp = NULL;
		tcp = data + nh_off + sizeof(*ip);
		if (data + nh_off + sizeof(*ip) + sizeof(*tcp) > data_end)
			goto DROP;
		pkt.src_port = tcp->source;
		pkt.dst_port = PORT(tcp->dest);
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *udp = NULL;
		udp = data + nh_off + sizeof(*ip);
		if (data + nh_off + sizeof(*ip) + sizeof(*udp) > data_end)
			goto DROP;
		pkt.src_port = udp->source;
		pkt.dst_port = PORT(udp->dest);
		break;
	}
	default:
		goto DROP;
	}

	uint32_t zero = 0;
	struct countmin *cm;
#if PRINT_TIME
	u64 start;
	start = bpf_ktime_get_ns();
#endif
	cm = bpf_map_lookup_elem(&countmin, &zero);

	if (!cm) {
		bpf_printk("Invalid entry in the countmin sketch");
		goto DROP;
	}

#ifdef SK_CM_EMPTY_HASH
	_Static_assert(
		sizeof(pkt) >= 4,
		"pkt size must be at least 4 bytes (for empty hash to work)");
#endif
	countmin_add(cm, &pkt, sizeof(pkt));

#if PRINT_TIME
	bpf_printk("countmin time %llu", bpf_ktime_get_ns() - start);
#endif

#if RECORD
	struct pkt_md *md;
	uint32_t index = 0;
	md = bpf_map_lookup_elem(&dropcnt, &index);
	if (md) {
#if _COUNT_PACKETS == 1
		NO_TEAR_INC(md->drop_cnt);
#endif
#if _COUNT_BYTES == 1
		uint16_t pkt_len = (uint16_t)(data_end - data);
		NO_TEAR_ADD(md->bytes_cnt, pkt_len);
#endif
	}
#endif

#if _ACTION_DROP
	return DROP_ACTION;
#else
	return bpf_redirect(_OUTPUT_INTERFACE_IFINDEX, 0);
#endif

DROP:
	bpf_printk("Error. Dropping packet\n");
	return XDP_DROP;
}
