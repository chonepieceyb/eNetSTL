// simdnn.bpf.c

#include "../common.h"
#include "common.h"

/* kfunc declarations for neural network inference */
extern int bpf_nm_inference(void *model, int model_size__sz, void *attr, int attr_size__sz) __ksym;

char _license[] SEC("license") = "GPL";

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

struct model2 {
    struct fc_layer     fc1;           
    struct relu_layer   relu1;
    struct fc_layer     fc2;         
    struct relu_layer   relu2;
    struct fc_layer     fc3;         
    struct relu_layer   relu3;
    struct fc_layer     fc_out;    
    struct output_layer output_buffer; 
};

typedef struct model2 nn_model;


/* --------- Flow map --------- */
#ifndef FLOW_MAP_DEFINE
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct flow);
    __type(value, struct flow_attribute);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_map SEC(".maps");
#endif

/* --------- Model map：value = struct model --------- */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, nn_model);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} model_map SEC(".maps");


/* --------- Kfunc --------- */

/* --------- 特征统计/提取/归一化 --------- */
static __always_inline void update_flow_stats(struct flow *flow_key,
                                              struct flow_attribute *fa,
                                              __u64 now_ns, __u32 packet_len)
{
    fa->num_packet++;
    if (fa->num_packet == 1)
    {
        fa->min_packet_length = packet_len;
        fa->max_packet_length = packet_len;
    }
    else
    {
        if (packet_len < fa->min_packet_length)
            fa->min_packet_length = packet_len;
        if (packet_len > fa->max_packet_length)
            fa->max_packet_length = packet_len;
    }
    if (fa->last_packet_time > 0)
    {
        __u64 dt = now_ns - fa->last_packet_time;
        if (dt > (__u64)fa->max_duration)
            fa->max_duration = dt;
    }
    fa->last_packet_time = now_ns;
    fa->dst_port = flow_key->dport;
}

static __always_inline void extract_features(struct flow_attribute *fa, int *attr)
{
#pragma clang loop unroll(full)
    for (int i = 0; i < 6; i++)
        attr[i] = 0;

    attr[0] = fa->num_packet;
    attr[1] = fa->min_packet_length;
    attr[2] = fa->max_packet_length;
    attr[3] = fa->max_duration;
    attr[4] = fa->dst_port;
    attr[5] = fa->header_length;
}

static __always_inline void normalize_features(int *attr)
{
#pragma clang loop unroll(full)
    for (int i = 0; i < 6; i++)
    {
        long long sc = scale[i];
        if (sc != 0)
        {
            long long t = ((long long)attr[i] - mean[i]);
            attr[i] = (int)((unsigned long long)(t * (1LL << FIX_POINT)) / (unsigned long long)sc);
        }
    }
}

PACKET_COUNT_MAP_DEFINE

/* --------- XDP 主程序 --------- */
SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	LATENCY_START_TIMESTAMP_DEFINE
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/* L2 */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		log_error("Invalid ethernet header");
		return XDP_DROP;
	}
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		log_error("Non-IP packet detected");
		return XDP_DROP;
	}

	/* L3 */
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		log_error("Invalid IP header");
		return XDP_DROP;
	}
	if (ip->protocol != IPPROTO_TCP) {
		log_error("Non-TCP packet detected");
		return XDP_DROP;
	}

	/* L4 */
	struct tcphdr *tcp = (void *)(ip + 1);
	if ((void *)(tcp + 1) > data_end) {
		log_error("Invalid TCP header");
		return XDP_DROP;
	}

	/* flow key */
	struct flow key = {
		.saddr = ip->saddr,
		.sport = tcp->source,
		.daddr = ip->daddr,
		.dport = tcp->dest,
	};

	/* 取/更新 flow 统计 */
	struct flow_attribute *fa = bpf_map_lookup_elem(&flow_map, &key);

	//__u64 now_ns = bpf_ktime_get_ns();
	__u64 now_ns = __get_bpf_ktime();
	__u32 pkt_len = (__u32)((long)data_end - (long)data);

	if (!fa)
	{
		struct flow_attribute new_fa = {0};
		bpf_map_update_elem(&flow_map, &key, &new_fa, BPF_ANY);
		fa = bpf_map_lookup_elem(&flow_map, &key);
		if (!fa) {
		log_error("flow_map update failed");
		return XDP_DROP;
		}
	}
	fa->last_packet_time = now_ns;
	fa->header_length = sizeof(*eth) + sizeof(*ip) + sizeof(*tcp);
	fa->detection_start_time = now_ns;
	update_flow_stats(&key, fa, now_ns, pkt_len);
	
	int attr[6] = {0};

	/* 提+归一化特征（6 维，很小） */
	extract_features(fa, attr);
	normalize_features(attr);

	/* 模型实例（value: struct model） */
	__u32 model_key = 0;
	nn_model *m = bpf_map_lookup_elem(&model_map, &model_key);
	if (!m)
	{
		log_error("model_map empty");
		return XDP_DROP;
	}

	// TODO: 测试kfunc
	log_debug("model size %llu", sizeof(*m));
	log_debug("output layer type %d", m->fc_out.comm.type);
	log_debug("output layer off %d", m->fc_out.comm.next_layer_off);
	int ret = 0;
	ret = bpf_nm_inference(m, sizeof(*m), attr, sizeof(attr));
	if (ret < 0) {
		log_error("inference failed: %d", ret);
		return XDP_DROP;
	}

	/* 读取输出（2 维），做 argmax */
	int y0 = m->output_buffer.buffer[0];
	int y1 = m->output_buffer.buffer[1];
	int pred = (y0 >= y1) ? 0 : 1;

	/* 计算检测时间并输出 */
	// __u64 detection_end_time = bpf_ktime_get_ns();
	__u64 detection_end_time = __get_bpf_ktime();
	__u64 detection_time = detection_end_time - fa->detection_start_time;
	log_debug("Detection result: %d, detection time: %llu ns", pred, detection_time);

	PACKET_COUNT_MAP_UPDATE

#ifdef LATENCY_EXP
	SWAP_MAC_AND_RETURN_XDP_TX(ctx)
#endif

#if LOG_LEVEL >= LOG_LEVEL_DEBUG
	return XDP_PASS;
#else
    	return XDP_DROP;
#endif 
}
