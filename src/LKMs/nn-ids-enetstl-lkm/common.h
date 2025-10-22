#ifndef SIMDNN_COMMON_H
#define SIMDNN_COMMON_H

#include "./mlp_params.bpf.h"
#include <linux/types.h>
#include <linux/kernel.h>
#include <asm/fpu/api.h>
#include <asm/cpufeature.h>

/* ---- Layer types ---- */
#define ENETSTL_FC_LAYER 1
#define ENETSTL_RELU_LAYER 2
#define ENETSTL_OUTPUT_LAYER 3

#ifdef __KERNEL__
/* 避免 xmmintrin.h -> mm_malloc.h 再去 #include <stdlib.h> */
#define _MM_MALLOC_H 1
#endif

#ifdef __AVX2__
#include <immintrin.h>   /* __m256i / AVX2 intrinsics */
#endif

/* ---- Common header ---- */
struct layer_common
{
    int type;           /* ENETSTL_* */
    int next_layer_off; /* byte offset from struct model base; 0 => end */
};

/* ---- FC params / size ---- */
struct fc_layer_parms
{
    int in_features;
    int out_features;
};

/* ---- Layers ---- */
struct fc_layer
{
    struct layer_common comm;
    struct fc_layer_parms parm;
    int weights[64][64];
};

struct relu_layer
{
    struct layer_common comm;
    int feature_num;
};

struct output_layer
{
    struct layer_common comm;
    int buffer[2];
};

/* ---- Flow structs ---- */
struct flow
{
    int saddr;
    int sport;
    int daddr;
    int dport;
};

struct flow_attribute
{
    __s64 num_packet;
    __s64 min_packet_length;
    __s64 max_packet_length;
    __s64 max_duration;
    __s64 dst_port;
    __s64 header_length;

    __s64 last_packet_time;
    __s64 status;
    __u64 total_feature_extraction_time;
    __u64 detection_start_time;
};

/* ---- model ---- */
struct model
{
    struct fc_layer fc1;
    struct relu_layer relu1;
    struct fc_layer fc2;
    struct relu_layer relu2;
    struct fc_layer fc_out;
    struct output_layer output_buffer;
};

#endif /* SIMDNN_COMMON_H */
