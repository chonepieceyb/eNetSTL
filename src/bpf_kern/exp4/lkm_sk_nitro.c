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

#include "../common.h"

#include "sk_common.h"
#include "sk_config.h"

char _license[] SEC("license") = "GPL";

_Static_assert((COLUMNS & (COLUMNS - 1)) == 0,
	       "COLUMNS must be a power of two");

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

struct {
	__uint(type, BPF_MAP_TYPE_STATIC_CUSTOM_MAP);
	__type(key, struct pkt_5tuple);
	__type(value, __u32); /*must be __u32/u32 */
	__uint(max_entries, (HASHFN_N << 16) + COLUMNS);
} sketch_lkm SEC(".maps");

#if RECORD
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct pkt_md);
	__uint(max_entries, 1);
} metadata SEC(".maps");
#endif

PACKET_COUNT_MAP_DEFINE

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	LATENCY_START_TIMESTAMP_DEFINE

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	int res;
	uint32_t zero = 0;
	struct pkt_md *md;
	int value = 1;

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

	res = bpf_map_update_elem(&sketch_lkm, &pkt, &value, 0);
	if (res < 0) {
		bpf_printk("failed to update nitro sketch\n, %d", res);
		goto DROP;
	}
SKIP:;
#if RECORD
	md = bpf_map_lookup_elem(&metadata, &zero);
	if (!md) {
		bpf_printk("Error! Invalid metadata.");
		goto DROP;
	}
#if _COUNT_PACKETS == 1
	NO_TEAR_INC(md->drop_cnt);
#endif
#if _COUNT_BYTES == 1
	uint16_t pkt_len = (uint16_t)(data_end - data);
	NO_TEAR_ADD(md->bytes_cnt, pkt_len);
#endif

#endif

	PACKET_COUNT_MAP_UPDATE
#ifdef LATENCY_EXP
	SWAP_MAC_AND_RETURN_XDP_TX(ctx) 
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
