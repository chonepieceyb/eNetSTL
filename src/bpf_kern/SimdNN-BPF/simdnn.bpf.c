// simdnn.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/errno.h>

#include "common.h" // 上面的头

char _license[] SEC("license") = "GPL";

/* --------- log 宏 --------- */
#ifndef LOG_LEVEL
#define LOG_LEVEL 2
#endif
#if LOG_LEVEL >= 3
#define log_debug(fmt, ...) bpf_printk("[DEBUG] " fmt, ##__VA_ARGS__)
#else
#define log_debug(fmt, ...)
#endif
#if LOG_LEVEL >= 2
#define log_info(fmt, ...) bpf_printk("[INFO] " fmt, ##__VA_ARGS__)
#else
#define log_info(fmt, ...)
#endif
#if LOG_LEVEL >= 1
#define log_warn(fmt, ...) bpf_printk("[WARN] " fmt, ##__VA_ARGS__)
#else
#define log_warn(fmt, ...)
#endif
#if LOG_LEVEL >= 0
#define log_error(fmt, ...) bpf_printk("[ERROR] " fmt, ##__VA_ARGS__)
#else
#define log_error(fmt, ...)
#endif

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/* --------- Flow map（按你工程里的宏；若没有就自行定义） --------- */
#ifndef FLOW_MAP_DEFINE
/* 兜底定义：LRU hash，按需替换为你现有的 FLOW_MAP_DEFINE */
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
    __type(value, struct model);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} model_map SEC(".maps");

/* --------- Input map --------- */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, int[6]);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} input_map SEC(".maps");

/* --------- Stats map --------- */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} stats_map SEC(".maps");

/* --------- Kfunc --------- */
// bpf_nm_inference(void *model, int model_size_sz, void *attr, int attr_size_sz);

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
            attr[i] = (int)((t * (1LL << FIX_POINT)) / sc);
        }
    }
}

/* --------- XDP 主程序（按需改成 TC hook） --------- */
SEC("xdp")
int xdp_simdnn_main(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* L2 */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* L3 */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* L4 */
    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    /* flow key */
    struct flow key = {
        .saddr = ip->saddr,
        .sport = tcp->source,
        .daddr = ip->daddr,
        .dport = tcp->dest,
    };

    /* 取/更新 flow 统计 */
    struct flow_attribute *fa = bpf_map_lookup_elem(&flow_map, &key);
    struct flow_attribute new_fa = {};
    __u64 now_ns = bpf_ktime_get_ns();
    __u32 pkt_len = (__u32)((long)data_end - (long)data);

    if (!fa)
    {
        new_fa.last_packet_time = now_ns;
        new_fa.header_length = sizeof(*eth) + sizeof(*ip) + sizeof(*tcp);
        new_fa.detection_start_time = now_ns;
        fa = &new_fa;
    }
    update_flow_stats(&key, fa, now_ns, pkt_len);
    bpf_map_update_elem(&flow_map, &key, fa, BPF_ANY);

    /* 收集到一定数量再推理（阈值按需调整） */
    if (fa->num_packet < 10)
        return XDP_PASS;

    __u32 input_buffer_id = 0;
    int *attr = bpf_map_lookup_elem(&input_map, &input_buffer_id);
    if (!attr)
    {
        log_error("input_map lookup failed");
        return XDP_PASS;
    }

    /* 提+归一化特征（6 维，很小） */
    int attr[6];
    extract_features(fa, attr);
    normalize_features(attr);

    /* 模型实例（value: struct model） */
    __u32 model_id = 0;
    struct model *m = bpf_map_lookup_elem(&model_map, &model_id);
    if (!m)
    {
        log_error("model_map empty");
        return XDP_PASS;
    }

    // TODO
    int ret = bpf_nm_inference(m, sizeof(*m), attr, sizeof(attr));
    if (ret)
    {
        log_error("inference failed: %d", ret);
        return XDP_PASS;
    }

    /* 读取输出（2 维），做 argmax */
    int y0 = m->output_buffer.buffer[0];
    int y1 = m->output_buffer.buffer[1];
    int pred = (y0 >= y1) ? 0 : 1;

    /* 统计计数 */
    __u64 *st = bpf_map_lookup_elem(&stats_map, &idx0);
    if (st)
        __sync_fetch_and_add(st, 1);

    log_info("Flow %x:%d -> %x:%d classified as %d",
             key.saddr, key.sport, key.daddr, key.dport, pred);

    /* 可选：重置该 flow 的统计以便下一次检测 */
    __builtin_memset(fa, 0, sizeof(*fa));
    bpf_map_update_elem(&flow_map, &key, fa, BPF_ANY);

    return XDP_PASS;
}
