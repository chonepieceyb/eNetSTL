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

#include <bpf/bpf_endian.h>
#include "../common.h"
#include "../vmlinux.h"
#include "./sk_config.h"

char _license[] SEC("license") = "GPL";

PACKET_COUNT_MAP_DEFINE

_Static_assert((COLUMNS & (COLUMNS - 1)) == 0,
	       "COLUMNS must be a power of two");

struct pkt_5tuple_with_pad {
	struct pkt_5tuple pkt;
	uint8_t __pad[3];
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_STATIC_CUSTOM_MAP);
	__type(key, struct pkt_5tuple_with_pad);
	__type(value, __u32); /*must be __u32/u32 */
	__uint(max_entries, 1);
} sketch_lkm SEC(".maps");

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	LATENCY_START_TIMESTAMP_DEFINE

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };
	struct pkt_5tuple_with_pad pkt;
	uint32_t zero = 0;
	struct countmin *cm;
	int ret = 0;
	int value = 1;
	if ((ret = parse_pkt_5tuple(&nh, data_end, &pkt.pkt)) != 0) {
		log_error(" failed to parse packet: %d", ret);
		goto out;
	}
	ret = bpf_map_update_elem(&sketch_lkm, &pkt, &value, 0);
	if (ret < 0) {
		bpf_printk("failed to update nitro sketch\n, %d", ret);
	}

	PACKET_COUNT_MAP_UPDATE

#ifdef LATENCY_EXP
	SWAP_MAC_AND_RETURN_XDP_TX(ctx) 
#endif
out:
	return XDP_DROP;
}
