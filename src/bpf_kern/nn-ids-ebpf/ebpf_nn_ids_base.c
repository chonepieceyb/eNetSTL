// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include "../common.h"
#include "params.bpf.h"
#include "common.bpf.h"
#include "handler.bpf.h"
#include "mlp.bpf.h"

#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/

struct
{
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u32);
    __uint(pinning, 1);
} progs SEC(".maps");

static inline int flow_tuple(struct xdp_md *ctx, struct flow *f)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;

    if (eth + 1 > (struct ethhdr *)data_end)
    {
        log_error("Ethernet header out of bounds in flow_tuple");
        return -1;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        log_error("Non-IPv4 packet in flow_tuple");
        return -1;
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip + 1 > (struct iphdr *)data_end)
    {
        log_error("IP header out of bounds in flow_tuple");
        return -1;
    }

    if (ip->protocol != IPPROTO_TCP)
    {
        log_error("Non-TCP packet in flow_tuple %d", ip->protocol);
        return -1;
    }

    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (tcp + 1 > (struct tcphdr *)data_end)
    {
        log_error("TCP header out of bounds in flow_tuple");
        return -1;
    }

    f->saddr = ip->saddr;
    f->daddr = ip->daddr;
    f->sport = tcp->source;
    f->dport = tcp->dest;

    return 0;
}

PACKET_COUNT_MAP_DEFINE

__u64 g_start_timestamp = 0;

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
    LATENCY_START_TIMESTAMP_DEFINE
    g_start_timestamp = start_timestamp;
    struct flow f = {};

    if (flow_tuple(ctx, &f) < 0)
    {
        log_error("Failed to parse flow tuple in xdp_prog");
        return XDP_DROP;
    }

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 33.33.33.73 == 555819337

    // if ((bpf_ntohs(tcp->dest) == 5001))
    // if ((bpf_ntohl(f.saddr) == 555819337))
    if (1)
    {
        struct iphdr *ip = data + sizeof(struct ethhdr);
        if (ip + 1 > (struct iphdr *)data_end)
        {
            log_error("IP header out of bounds in xdp_prog");
            return XDP_DROP;
        }

        struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if (tcp + 1 > (struct tcphdr *)data_end)
        {
            log_error("TCP header out of bounds in xdp_prog");
            return XDP_DROP;
        }

        u64 packet_length = bpf_ntohs(ip->tot_len) - ip->ihl * 4;

        update_flow_attribute(&f, tcp, packet_length);

        // if (tcp->fin || tcp->rst)
        // {
            // int32_t idx = 0;
            // int32_t *idx_ptr = bpf_map_lookup_elem(&nn_idx, &idx);
            // struct flow_attribute *attr_ptr = (struct flow_attribute *)bpf_map_lookup_elem(&flow_map, &f);

            // if (idx_ptr && attr_ptr)
            // {
            //     attr_ptr->nn_idx = *idx_ptr;
            //     bpf_tail_call(ctx, &progs, 0);
            //     log_error("failed to tail call to preprocessing program");
            // } else {
            //      log_error("failed to find idx_ptr or attr_ptr in xdp_prog");
            // }
        // }
        /*we do not need tail call */
        u64 start_timestamp = g_start_timestamp;
        PACKET_COUNT_MAP_UPDATE

        #ifdef LATENCY_EXP
            SWAP_MAC_AND_RETURN_XDP_TX(ctx)
        #endif
            return XDP_DROP;
    }
}

char __license[] SEC("license") = "GPL";