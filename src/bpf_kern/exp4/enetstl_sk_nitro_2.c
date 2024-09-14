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

#define SK_NITRO_UPDATE_PROB_PERCENT 2

#define MAX_GEOSAMPLING_SIZE 1024
#define ____cacheline_aligned __attribute__((aligned(64)))

typedef u32 geo_cnt_t;

struct geo_sampling_ctx {
	int fd;
	geo_cnt_t cnt;
	u32 geo_sampling_idx ____cacheline_aligned;
	geo_cnt_t pool[MAX_GEOSAMPLING_SIZE] ____cacheline_aligned;
};

extern struct geo_sampling_ctx *
bpf_geo_sampling_ctx_new(int prob_percent) __ksym;

extern void bpf_geo_sampling_ctx_free(struct geo_sampling_ctx *ctx) __ksym;

extern bool bpf_geo_sampling_should_do(int fd) __ksym;

extern geo_cnt_t bpf_geo_sampling_gen_geo_cnt(int fd) __ksym;

/**
 * bpf_crc32c_sse() - Calculate CRC32 hash on user-supplied byte array.
 *
 * @data: Data to perform hash on.
 * @data__sz: How many bytes to use to calculate hash value.
 * @init_val: Value to initialise hash generator.
 * 
 * Return: 32bit calculated hash value.
 */
extern uint32_t bpf_crc32c_sse(const void *data, uint32_t data__sz,
			       uint32_t init_val) __ksym;

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

struct geo_sampling_ctx_holder {
	struct geo_sampling_ctx __kptr *ctx;
	int fd_alt;
	geo_cnt_t cnt_alt;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct countmin);
	__uint(max_entries, 1);
} countmin SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct geo_sampling_ctx_holder);
	__uint(max_entries, 1);
} geo_sampling_ctx_map SEC(".maps");

PACKET_COUNT_MAP_DEFINE

static void FORCE_INLINE nitrosketch_countmin_add(struct countmin *cm,
						  void *element, __u64 len,
						  uint32_t row_to_update)
{
	for (int i = 0; i < HASHFN_N; i++) {
		__u32 hash = bpf_crc32c_sse(element, len, seeds[row_to_update]);
		__u32 target_idx = hash & (COLUMNS - 1);
		NO_TEAR_ADD(cm->values[row_to_update][target_idx], 1);
	}
	return;
}

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	LATENCY_START_TIMESTAMP_DEFINE

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	uint32_t zero = 0;

	struct geo_sampling_ctx_holder *geo_ctx_holder;
	geo_ctx_holder = bpf_map_lookup_elem(&geo_sampling_ctx_map, &zero);
	if (!geo_ctx_holder) {
		bpf_printk("Invalid entry in the geo sampling context map");
		goto DROP;
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

	if (!geo_ctx_holder->fd_alt) {
		struct geo_sampling_ctx *geo_ctx, *old_geo_ctx;
		geo_ctx =
			bpf_geo_sampling_ctx_new(SK_NITRO_UPDATE_PROB_PERCENT);
		if (geo_ctx == NULL) {
			bpf_printk("Error allocating geo sampling context");
			goto DROP;
		}
		geo_ctx_holder->fd_alt = geo_ctx->fd;
		old_geo_ctx = bpf_kptr_xchg(&geo_ctx_holder->ctx, geo_ctx);
		if (unlikely(old_geo_ctx != NULL)) {
			bpf_geo_sampling_ctx_free(old_geo_ctx);
		}
	}

	if (geo_ctx_holder->cnt_alt >= HASHFN_N) {
		geo_ctx_holder->cnt_alt -= HASHFN_N;
		log_debug("all rows are skipped");
		goto SKIP;
	}

	int fd = geo_ctx_holder->fd_alt;
	u32 row_to_update = (geo_ctx_holder->cnt_alt) & (HASHFN_N - 1);
	geo_cnt_t next_geo_value;
	for (int i = 0; i < HASHFN_N; i++) {
		asm_bound_check(row_to_update, HASHFN_N);
		nitrosketch_countmin_add(cm, &pkt, sizeof(pkt), row_to_update);
		log_debug("updated row %d", row_to_update);
		next_geo_value = bpf_geo_sampling_gen_geo_cnt(fd);
		row_to_update += next_geo_value;
		if (row_to_update >= HASHFN_N)
			break;
	}
	if (unlikely(next_geo_value == 0)) {
		log_error("gen_geo_cnt renturn zero, should not happen");
		goto SKIP;
	} else {
		geo_ctx_holder->cnt_alt = next_geo_value - 1;
	}
#if PRINT_TIME
	bpf_printk("nitro update : %llu\n", bpf_ktime_get_ns() - start);
#endif

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

// This is only used when the action is redirect
int xdp_dummy(struct xdp_md *ctx)
{
	return XDP_PASS;
}
