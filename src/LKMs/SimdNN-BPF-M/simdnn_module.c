#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/simd.h>
#include <asm/simd.h>
#include <immintrin.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include "../../bpf_kern/SimdNN-BPF/common.h"
#include "../../bpf_kern/SimdNN-BPF/mlp_params.bpf.h"

#define MAX_FLOWS 8192
#define FLOW_HT_BITS 13

// Layer types
#define ENETSTL_FC_LAYER 1
#define ENETSTL_RELU_LAYER 2

// Flow hash table
static DEFINE_HASHTABLE(flow_table, FLOW_HT_BITS);

struct flow_entry {
    struct hlist_node node;
    struct flow key;
    struct flow_attribute attr;
    struct rcu_head rcu;
};

// Global model instance
static struct model *global_model = NULL;

// Statistics
static atomic_t packets_processed = ATOMIC_INIT(0);
static atomic_t flows_classified = ATOMIC_INIT(0);

// Forward declarations
static int simdnn_fc_layer_forward(struct fc_layer *layer, int *input, int *output);
static int simdnn_relu_layer_forward(struct relu_layer *layer, int *input, int *output);
static void simdnn_simd_fc_forward(const int *weights, const int *bias, const int *input,
                                  int *output, int in_features, int out_features);
static struct flow_entry *find_or_create_flow(struct flow *key);
static void extract_features(struct flow_attribute *attr, int *features);
static void normalize_features(int *features);
static int perform_inference(int *input, int *output);

// Flow hash function
static inline u32 flow_hash(struct flow *key)
{
    return jhash2((u32 *)key, sizeof(*key) / sizeof(u32), 0);
}

// SIMD-accelerated fully connected layer forward pass
static void simdnn_simd_fc_forward(const int *weights, const int *bias, const int *input,
                                  int *output, int in_features, int out_features)
{
    int i, j;

    // For each output neuron
    for (i = 0; i < out_features; i++) {
        __m256i sum = _mm256_setzero_si256();

        // Process 8 elements at a time using AVX2
        int simd_chunks = in_features / 8;
        const int *weight_ptr = &weights[i * in_features];

        for (j = 0; j < simd_chunks; j++) {
            __m256i input_vec = _mm256_loadu_si256((__m256i*)&input[j * 8]);
            __m256i weight_vec = _mm256_loadu_si256((__m256i*)&weight_ptr[j * 8]);

            // Multiply and accumulate
            __m256i product = _mm256_mullo_epi32(input_vec, weight_vec);
            sum = _mm256_add_epi32(sum, product);
        }

        // Horizontal sum
        __m128i sum128 = _mm_add_epi32(_mm256_castsi256_si128(sum),
                                      _mm256_extracti128_si256(sum, 1));
        sum128 = _mm_add_epi32(sum128, _mm_shuffle_epi32(sum128, _MM_SHUFFLE(1, 0, 3, 2)));
        sum128 = _mm_add_epi32(sum128, _mm_shuffle_epi32(sum128, _MM_SHUFFLE(2, 3, 0, 1)));

        int total_sum = _mm_extract_epi32(sum128, 0);

        // Handle remaining elements
        for (j = simd_chunks * 8; j < in_features; j++) {
            total_sum += input[j] * weight_ptr[j];
        }

        // Add bias and store result
        output[i] = total_sum + bias[i];
    }
}

// Fully connected layer forward pass
static int simdnn_fc_layer_forward(struct fc_layer *layer, int *input, int *output)
{
    if (!layer || !input || !output) {
        return -EINVAL;
    }

    if (layer->comm.type != ENETSTL_FC_LAYER) {
        return -EINVAL;
    }

    simdnn_simd_fc_forward((const int *)layer->weights, layer->bias, input, output,
                           layer->parm.in_features, layer->parm.out_features);

    return 0;
}

// ReLU activation forward pass
static int simdnn_relu_layer_forward(struct relu_layer *layer, int *input, int *output)
{
    int i;

    if (!layer || !input || !output) {
        return -EINVAL;
    }

    if (layer->comm.type != ENETSTL_RELU_LAYER) {
        return -EINVAL;
    }

    // Apply ReLU: output[i] = max(0, input[i])
    for (i = 0; i < 32; i++) {
        output[i] = input[i] > 0 ? input[i] : 0;
    }

    return 0;
}

// Find or create flow entry
static struct flow_entry *find_or_create_flow(struct flow *key)
{
    struct flow_entry *entry;
    u32 hash = flow_hash(key);

    hash_for_each_possible_rcu(flow_table, entry, node, hash) {
        if (memcmp(&entry->key, key, sizeof(*key)) == 0) {
            return entry;
        }
    }

    // Create new entry
    entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry) {
        return NULL;
    }

    memcpy(&entry->key, key, sizeof(*key));
    hash_add_rcu(flow_table, &entry->node, hash);

    return entry;
}

// Extract features from flow attributes
static void extract_features(struct flow_attribute *attr, int *features)
{
    features[0] = attr->num_packet;
    features[1] = attr->min_packet_length;
    features[2] = attr->max_packet_length;
    features[3] = attr->max_duration;
    features[4] = attr->dst_port;
    features[5] = attr->header_length;
}

// Normalize features using pre-computed mean and scale
static void normalize_features(int *features)
{
    for (int i = 0; i < 6; i++) {
        if (scale[i] != 0) {
            features[i] = ((features[i] - mean[i]) * (1 << FIX_POINT)) / scale[i];
        }
    }
}

// Perform neural network inference
static int perform_inference(int *input, int *output)
{
    int temp_buffer1[32] = {0};
    int temp_buffer2[32] = {0};
    int *current_input, *current_output;
    int ret = 0;

    if (!global_model) {
        return -EINVAL;
    }

    kernel_fpu_begin();

    // Start with input buffer
    current_input = input;
    current_output = temp_buffer1;

    // Layer 1: FC -> ReLU
    ret = simdnn_fc_layer_forward(&global_model->fc1, current_input, current_output);
    if (ret) goto out;

    // ReLU activation
    current_input = current_output;
    current_output = temp_buffer2;
    ret = simdnn_relu_layer_forward(&global_model->relu1, current_input, current_output);
    if (ret) goto out;

    // Layer 2: FC -> ReLU
    current_input = current_output;
    current_output = temp_buffer1;
    ret = simdnn_fc_layer_forward(&global_model->fc2, current_input, current_output);
    if (ret) goto out;

    // ReLU activation
    current_input = current_output;
    current_output = temp_buffer2;
    ret = simdnn_relu_layer_forward(&global_model->relu2, current_input, current_output);
    if (ret) goto out;

    // Output layer: FC
    current_input = current_output;
    current_output = output;
    ret = simdnn_fc_layer_forward(&global_model->output, current_input, current_output);

out:
    kernel_fpu_end();
    return ret;
}

// Netfilter hook function
static unsigned int simdnn_nf_hook(void *priv, struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct ethhdr *eth;
    struct flow flow_key;
    struct flow_entry *flow_entry;
    u64 current_time;
    int features[6], output[2];
    int prediction;

    // Check if packet is IP
    if (!skb) return NF_ACCEPT;

    eth = eth_hdr(skb);
    if (!eth) return NF_ACCEPT;

    if (eth->h_proto != htons(ETH_P_IP)) {
        return NF_ACCEPT;
    }

    ip = ip_hdr(skb);
    if (!ip) return NF_ACCEPT;

    // Only process TCP packets
    if (ip->protocol != IPPROTO_TCP) {
        return NF_ACCEPT;
    }

    tcp = tcp_hdr(skb);
    if (!tcp) return NF_ACCEPT;

    // Create flow key
    flow_key.saddr = ip->saddr;
    flow_key.sport = tcp->source;
    flow_key.daddr = ip->daddr;
    flow_key.dport = tcp->dest;

    // Find or create flow entry
    flow_entry = find_or_create_flow(&flow_key);
    if (!flow_entry) {
        return NF_ACCEPT;
    }

    current_time = ktime_get_ns();

    // Update flow statistics
    flow_entry->attr.num_packet++;
    if (flow_entry->attr.num_packet == 1) {
        flow_entry->attr.min_packet_length = skb->len;
        flow_entry->attr.max_packet_length = skb->len;
        flow_entry->attr.header_length = sizeof(*eth) + sizeof(*ip) + sizeof(*tcp);
        flow_entry->attr.detection_start_time = current_time;
    } else {
        if (skb->len < flow_entry->attr.min_packet_length) {
            flow_entry->attr.min_packet_length = skb->len;
        }
        if (skb->len > flow_entry->attr.max_packet_length) {
            flow_entry->attr.max_packet_length = skb->len;
        }
    }

    if (flow_entry->attr.last_packet_time > 0) {
        u64 duration = current_time - flow_entry->attr.last_packet_time;
        if (duration > flow_entry->attr.max_duration) {
            flow_entry->attr.max_duration = duration;
        }
    }

    flow_entry->attr.last_packet_time = current_time;
    flow_entry->attr.dst_port = flow_key.dport;

    // Only perform inference after collecting enough packets
    if (flow_entry->attr.num_packet >= 10) {
        // Extract and normalize features
        extract_features(&flow_entry->attr, features);
        normalize_features(features);

        // Perform inference
        if (perform_inference(features, output) == 0) {
            prediction = output[0] > output[1] ? 0 : 1;

            atomic_inc(&flows_classified);
            pr_info("Flow %pI4:%d -> %pI4:%d classified as %d\n",
                    &flow_key.saddr, ntohs(flow_key.sport),
                    &flow_key.daddr, ntohs(flow_key.dport), prediction);

            // Reset flow after classification
            memset(&flow_entry->attr, 0, sizeof(flow_entry->attr));
        }
    }

    atomic_inc(&packets_processed);
    return NF_ACCEPT;
}

// Netfilter hook definition
static struct nf_hook_ops simdnn_nf_ops = {
    .hook = simdnn_nf_hook,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

// Initialize global model
static int init_global_model(void)
{
    global_model = kzalloc(sizeof(struct model), GFP_KERNEL);
    if (!global_model) {
        return -ENOMEM;
    }

    // Load model weights
    // Layer 1 weights (6 -> 32)
    for (int i = 0; i < 32; i++) {
        for (int j = 0; j < 6; j++) {
            global_model->fc1.weights[i][j] = layer_0_weight[i * 6 + j];
        }
        global_model->fc1.bias[i] = 0; // Bias not provided in params
    }

    // Layer 2 weights (32 -> 32)
    for (int i = 0; i < 32; i++) {
        for (int j = 0; j < 32; j++) {
            global_model->fc2.weights[i][j] = layer_1_weight[i * 32 + j];
        }
        global_model->fc2.bias[i] = 0; // Bias not provided in params
    }

    // Layer 3 weights (32 -> 2) - output layer
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 32; j++) {
            global_model->output.weights[i][j] = layer_2_weight[i * 32 + j];
        }
        global_model->output.bias[i] = 0; // Bias not provided in params
    }

    // Configure layer parameters
    global_model->fc1.comm.type = ENETSTL_FC_LAYER;
    global_model->fc1.comm.next_layer_off = offsetof(struct model, relu1);
    global_model->fc1.parm.in_features = 6;
    global_model->fc1.parm.out_features = 32;

    global_model->relu1.comm.type = ENETSTL_RELU_LAYER;
    global_model->relu1.comm.next_layer_off = offsetof(struct model, fc2);

    global_model->fc2.comm.type = ENETSTL_FC_LAYER;
    global_model->fc2.comm.next_layer_off = offsetof(struct model, relu2);
    global_model->fc2.parm.in_features = 32;
    global_model->fc2.parm.out_features = 32;

    global_model->relu2.comm.type = ENETSTL_RELU_LAYER;
    global_model->relu2.comm.next_layer_off = offsetof(struct model, output);

    global_model->output.comm.type = ENETSTL_FC_LAYER;
    global_model->output.comm.next_layer_off = 0;
    global_model->output.parm.in_features = 32;
    global_model->output.parm.out_features = 2;

    return 0;
}

static int __init simdnn_module_init(void)
{
    int ret;

    pr_info("SimdNN-BPF-M module loading\n");

    // Initialize hash table
    hash_init(flow_table);

    // Initialize global model
    ret = init_global_model();
    if (ret) {
        pr_err("Failed to initialize global model: %d\n", ret);
        return ret;
    }

    // Register netfilter hook
    ret = nf_register_net_hook(&init_net, &simdnn_nf_ops);
    if (ret) {
        pr_err("Failed to register netfilter hook: %d\n", ret);
        kfree(global_model);
        return ret;
    }

    pr_info("SimdNN-BPF-M module loaded successfully\n");
    return 0;
}

static void __exit simdnn_module_exit(void)
{
    struct flow_entry *entry;
    struct hlist_node *tmp;
    unsigned long bkt;

    pr_info("SimdNN-BPF-M module unloading\n");

    // Unregister netfilter hook
    nf_unregister_net_hook(&init_net, &simdnn_nf_ops);

    // Free flow table entries
    hash_for_each_safe(flow_table, bkt, tmp, entry, node) {
        hash_del_rcu(&entry->node);
        kfree_rcu(entry, rcu);
    }

    // Free global model
    kfree(global_model);

    pr_info("Packets processed: %d\n", atomic_read(&packets_processed));
    pr_info("Flows classified: %d\n", atomic_read(&flows_classified));
    pr_info("SimdNN-BPF-M module unloaded\n");
}

module_init(simdnn_module_init);
module_exit(simdnn_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("eNetSTL");
MODULE_DESCRIPTION("SimdNN-BPF-M pure kernel module implementation");
MODULE_VERSION("1.0");