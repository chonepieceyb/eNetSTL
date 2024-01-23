/*
 * Copyright 2021 Sebastiano Miano <mianosebastiano@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "common.h"
#include "sk_common.h"
#include <bpf/bpf_endian.h>

#include "common.h"
#include "sk_config.h"
#include "fasthash.h"
#include "xxhash.h"

// #define SK_NITRO_EMPTY_HASH

char _license[] SEC("license") = "GPL";

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

_Static_assert((COLUMNS & (COLUMNS - 1)) == 0,
	       "COLUMNS must be a power of two");

struct countmin {
	__u32 values[HASHFN_N][COLUMNS];
};

struct pkt_md {
	uint32_t cnt;
	uint32_t geo_sampling_idx;
#if RECORD
#if _COUNT_PACKETS == 1
	uint64_t drop_cnt;
#endif
#if _COUNT_BYTES == 1
	uint64_t bytes_cnt;
#endif
#endif
	uint32_t geo_sampling_array[MAX_GEOSAMPLING_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct countmin);
	__uint(max_entries, 1);
} countmin SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct pkt_md);
	__uint(max_entries, 1);
} metadata SEC(".maps");

static void FORCE_INLINE nitrosketch_countmin_add(struct countmin *cm,
						  void *element, __u64 len,
						  uint32_t row_to_update)
{
	for (int i = 0; i < HASHFN_N; i++) {
#ifdef SK_NITRO_EMPTY_HASH
		__u32 hash = ((const __u32 *)element)[(len >> 2) - 1] ^
			     seeds[row_to_update];
#else
#if USE_XXHASH == 1
		__u32 hash = xxh32(element, len, seeds[row_to_update]);
#else
		__u32 hash = fasthash32(element, len, seeds[row_to_update]);
#endif
#endif
		__u32 target_idx = hash & (COLUMNS - 1);
		NO_TEAR_ADD(cm->values[row_to_update][target_idx], 1);
	}
	return;
}

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	uint32_t zero = 0;
	struct pkt_md *md;

	md = bpf_map_lookup_elem(&metadata, &zero);
	if (!md) {
		bpf_printk("Error! Invalid metadata.");
		goto DROP;
	}

	if (md->cnt >= HASHFN_N) {
		md->cnt -= HASHFN_N;
		goto SKIP;
	}

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
#if PRINT_TIME
	u64 start;
	start = bpf_ktime_get_ns();
#endif
	struct countmin *cm;
	cm = bpf_map_lookup_elem(&countmin, &zero);

	if (!cm) {
		bpf_printk("Invalid entry in the countmin sketch");
		goto DROP;
	}

	uint32_t row_to_update;
	uint32_t next_geo_value;

	// This is required otherwise the verifier triggers an error
	bpf_probe_read_kernel(&row_to_update, sizeof(row_to_update), &md->cnt);

	// In the worst case, we do HASHFN_N cycles to update the counters
	// But in most of the case we jump out of the cycle because of the
	// geometric variable that increases the row_to_update

	for (int i = 0; i < HASHFN_N; i++) {
		// Here we start updating the sketch
		//nitrosketch_add_with_hash(cm, hashes, row_to_update);
#ifdef SK_NITRO_EMPTY_HASH
		_Static_assert(
			sizeof(pkt) >= 4,
			"pkt size must be at least 4 bytes (for empty hash to work)");
#endif
		nitrosketch_countmin_add(cm, &pkt, sizeof(pkt),
					 row_to_update & (HASHFN_N - 1));

		// We should now generate again a new discrete variable for the geometric sampling
		uint32_t geo_value_idx = md->geo_sampling_idx;

		geo_value_idx = (geo_value_idx + 1) &
				(MAX_GEOSAMPLING_SIZE - 1);
		next_geo_value = md->geo_sampling_array[geo_value_idx];
		row_to_update += next_geo_value;
		// geo_value_idx = (geo_value_idx + 1) & (MAX_GEOSAMPLING_SIZE - 1);
		md->geo_sampling_idx = geo_value_idx;

		if (row_to_update >= HASHFN_N)
			break;
	}
#if PRINT_TIME
	bpf_printk("nitro update : %llu\n", bpf_ktime_get_ns() - start);
#endif

	if (next_geo_value > 0) {
		md->cnt = next_geo_value - 1;
	} else {
		bpf_printk(
			"Geo sammpling variable is 0. This should never happen");
		goto DROP;
	}

SKIP:;
#if RECORD
#if _COUNT_PACKETS == 1
	NO_TEAR_INC(md->drop_cnt);
#endif
#if _COUNT_BYTES == 1
	uint16_t pkt_len = (uint16_t)(data_end - data);
	NO_TEAR_ADD(md->bytes_cnt, pkt_len);
#endif
#endif

#if _ACTION_DROP
	return DROP_ACTION;
#else
	return bpf_redirect(_OUTPUT_INTERFACE_IFINDEX, 0);
#endif

DROP:;
	bpf_printk("Error. Dropping packet\n");
	return XDP_DROP;
}

// This is only used when the action is redirect
int xdp_dummy(struct xdp_md *ctx)
{
	return XDP_PASS;
}
