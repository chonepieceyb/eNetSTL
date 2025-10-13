#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/errno.h>
#include "../common.h"
#include "common.h"
#include "mlp_params.bpf.h"

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

FLOW_MAP_DEFINE

// Model instance
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct model);
} model_map SEC(".maps");

// Statistics map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

static __always_inline void update_flow_stats(struct flow *flow_key, struct flow_attribute *flow_attr,
                                            __u64 current_time, __u32 packet_len) {
    // Update packet count
    flow_attr->num_packet++;

    // Update packet length stats
    if (flow_attr->num_packet == 1) {
        flow_attr->min_packet_length = packet_len;
        flow_attr->max_packet_length = packet_len;
    } else {
        if (packet_len < flow_attr->min_packet_length) {
            flow_attr->min_packet_length = packet_len;
        }
        if (packet_len > flow_attr->max_packet_length) {
            flow_attr->max_packet_length = packet_len;
        }
    }

    // Update duration
    if (flow_attr->last_packet_time > 0) {
        __u64 duration = current_time - flow_attr->last_packet_time;
        if (duration > flow_attr->max_duration) {
            flow_attr->max_duration = duration;
        }
    }

    flow_attr->last_packet_time = current_time;
    flow_attr->dst_port = flow_key->dport;
}

static __always_inline void extract_features(struct flow_attribute *flow_attr, int *features) {
    // Extract 6 features from flow attributes
    features[0] = flow_attr->num_packet;
    features[1] = flow_attr->min_packet_length;
    features[2] = flow_attr->max_packet_length;
    features[3] = flow_attr->max_duration;
    features[4] = flow_attr->dst_port;
    features[5] = flow_attr->header_length;
}

static __always_inline void normalize_features(int *features) {
    // Apply normalization using mean and scale from mlp_params.bpf.h
    for (int i = 0; i < 6; i++) {
        if (scale[i] != 0) {
            features[i] = ((features[i] - mean[i]) * (1 << FIX_POINT)) / scale[i];
        }
    }
}

SEC("xdp")
int xdp_simdnn_main(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end) {
        return XDP_PASS;
    }

    // Only process TCP packets
    if (ip->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*ip);
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end) {
        return XDP_PASS;
    }

    // Create flow key
    struct flow flow_key = {
        .saddr = ip->saddr,
        .sport = tcp->source,
        .daddr = ip->daddr,
        .dport = tcp->dest
    };

    // Get or create flow attribute
    struct flow_attribute *flow_attr = bpf_map_lookup_elem(&flow_map, &flow_key);
    struct flow_attribute new_attr = {0};

    __u64 current_time = bpf_ktime_get_ns();
    __u32 packet_len = data_end - data;

    if (!flow_attr) {
        // Initialize new flow attribute
        new_attr.last_packet_time = current_time;
        new_attr.header_length = sizeof(*eth) + sizeof(*ip) + sizeof(*tcp);
        new_attr.detection_start_time = current_time;
        flow_attr = &new_attr;
    }

    // Update flow statistics
    update_flow_stats(&flow_key, flow_attr, current_time, packet_len);

    // Update flow in map
    bpf_map_update_elem(&flow_map, &flow_key, flow_attr, BPF_ANY);

    // Only perform inference after collecting enough packets
    if (flow_attr->num_packet < 10) {
        return XDP_PASS;
    }

    // Extract and normalize features
    int features[6];
    extract_features(flow_attr, features);
    normalize_features(features);

    // Get model from map
    __u32 model_idx = 0;
    struct model *model = bpf_map_lookup_elem(&model_map, &model_idx);
    if (!model) {
        log_error("Model not found in map");
        return XDP_PASS;
    }

    // Copy features to model input buffer
    for (int i = 0; i < 6; i++) {
        model->input_buffer[i] = features[i];
    }

    // Configure model layers
    model->fc1.comm.type = ENETSTL_FC_LAYER;
    model->fc1.comm.next_layer_off = offsetof(struct model, relu1);
    model->fc1.parm.in_features = 6;
    model->fc1.parm.out_features = 32;

    model->relu1.comm.type = ENETSTL_RELU_LAYER;
    model->relu1.comm.next_layer_off = offsetof(struct model, fc2);

    model->fc2.comm.type = ENETSTL_FC_LAYER;
    model->fc2.comm.next_layer_off = offsetof(struct model, relu2);
    model->fc2.parm.in_features = 32;
    model->fc2.parm.out_features = 32;

    model->relu2.comm.type = ENETSTL_RELU_LAYER;
    model->relu2.comm.next_layer_off = offsetof(struct model, output);

    model->output.comm.type = ENETSTL_FC_LAYER;
    model->output.comm.next_layer_off = 0; // End of model
    model->output.parm.in_features = 32;
    model->output.parm.out_features = 2;

    // Perform neural network inference using kfunc
    int ret = bpf_nm_inference(model, sizeof(*model));
    if (ret != 0) {
        log_error("Neural network inference failed: %d", ret);
        return XDP_PASS;
    }

    // Get inference result
    int prediction = model->output_buffer[0] > model->output_buffer[1] ? 0 : 1;

    // Update statistics
    __u32 stats_idx = 0;
    __u64 *stats = bpf_map_lookup_elem(&stats_map, &stats_idx);
    if (stats) {
        __sync_fetch_and_add(stats, 1);
    }

    log_info("Flow %x:%d -> %x:%d classified as %d",
             flow_key.saddr, flow_key.sport, flow_key.daddr, flow_key.dport, prediction);

    // Reset flow after classification to start fresh
    __builtin_memset(flow_attr, 0, sizeof(*flow_attr));
    bpf_map_update_elem(&flow_map, &flow_key, flow_attr, BPF_ANY);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";