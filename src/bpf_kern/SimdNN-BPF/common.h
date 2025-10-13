#ifndef SIMDNN_COMMON_H
#define SIMDNN_COMMON_H

#include <linux/types.h>

// Layer types for neural network
#define ENETSTL_FC_LAYER 1
#define ENETSTL_RELU_LAYER 2

// Common layer structure
struct layer_common {
    int type;
    int next_layer_off;
};

// Fully connected layer parameters
struct fc_layer_parms {
    int in_features;
    int out_features;
};

// Flow key structure
struct flow {
    int saddr;
    int sport;
    int daddr;
    int dport;
};

// Flow attributes structure
struct flow_attribute
{
    __s64 num_packet;        // Number of packets
    __s64 min_packet_length; // Minimum length of a packet
    __s64 max_packet_length; // Maximum length of a packet
    __s64 max_duration;      // Maximum time between two packets sent in the forward direction
    __s64 dst_port;          // Destination port
    __s64 header_length;     // TCP total header length

    __s64 last_packet_time;
    __s64 status;
    __u64 total_feature_extraction_time;
    __u64 detection_start_time;
};

// User defined full connected layer
struct fc_layer {
    struct layer_common comm; // common fields for all layers
    struct fc_layer_parms parm; // parameters depend on comm.type
    // below are user provided data
    int weights[32][6];
    int bias[32];
};

// User defined ReLU layer
struct relu_layer {
    struct layer_common comm;
};

// User defined DNN model
struct model {
   struct fc_layer fc1;
   struct relu_layer relu1;
   struct fc_layer fc2;
   struct relu_layer relu2;
   struct fc_layer output;
   int input_buffer[6];
   int output_buffer[2];
};

#define MAX_PACKET_RECORD 8192

// Flow map definition for eBPF
#define FLOW_MAP_DEFINE \
    struct { \
        __uint(type, BPF_MAP_TYPE_HASH); \
        __uint(max_entries, MAX_PACKET_RECORD); \
        __type(key, struct flow); \
        __type(value, struct flow_attribute); \
    } flow_map SEC(".maps");

// Kfunc declaration for neural network inference
extern int bpf_nm_inference(void *model, int model_size) __ksym;

#endif // SIMDNN_COMMON_H