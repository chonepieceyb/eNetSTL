#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "../test_helpers.h"
#include "../bpf_skel/simdnn.bpf.skel.h"                  // skeleton（包含 xdp_simdnn_main 和各 maps）
#include "../../bpf_kern/nn-ids-enetstl/mlp_params.bpf.h" // N0..N3 和 layer_* 权重（与内核侧一致）
#include "common_user.h"                                  // layer_common、layer_fc、layer_relu、model

static int setup_maps_before_load(void *opaque_skel)
{
    return 0;
}

/* ====== 把 3 层 FC 权重装进 model_map[0] ====== */
static int setup_maps_after_load(void *opaque_skel)
{
    struct simdnn_bpf *skel = opaque_skel;
    __u32 key0 = 0;
    struct model model = (struct model){0};

    /* fc1: N0 -> N1 */
    model.fc1.comm.type = ENETSTL_FC_LAYER;
    model.fc1.comm.next_layer_off = (int)offsetof(struct model, relu1);
    model.fc1.parm.in_features = N0;
    model.fc1.parm.out_features = N1;
    for (int i = 0; i < N1; i++)
    {
        for (int j = 0; j < N0; j++)
            model.fc1.weights[i][j] = layer_0_weight[i * N0 + j];
    }

    /* relu1 -> fc2 */
    model.relu1.comm.type = ENETSTL_RELU_LAYER;
    model.relu1.comm.next_layer_off = (int)offsetof(struct model, fc2);
    model.relu1.feature_num = N1;

    /* fc2: N1 -> N2 */
    model.fc2.comm.type = ENETSTL_FC_LAYER;
    model.fc2.comm.next_layer_off = (int)offsetof(struct model, relu2);
    model.fc2.parm.in_features = N1;
    model.fc2.parm.out_features = N2;
    for (int i = 0; i < N2; i++)
    {
        for (int j = 0; j < N1; j++)
            model.fc2.weights[i][j] = layer_1_weight[i * N1 + j];
    }

    /* relu2 -> fc_out -> output_buffer(终止) */
    model.relu2.comm.type = ENETSTL_RELU_LAYER;
    model.relu2.comm.next_layer_off = (int)offsetof(struct model, fc_out);
    model.relu2.feature_num = N2;

    model.fc_out.comm.type = ENETSTL_FC_LAYER;
    model.fc_out.comm.next_layer_off = (int)offsetof(struct model, output_buffer);
    model.fc_out.parm.in_features = N2;
    model.fc_out.parm.out_features = N3;
    for (int i = 0; i < N3; i++)
    {
        for (int j = 0; j < N2; j++)
            model.fc_out.weights[i][j] = layer_2_weight[i * N2 + j];
    }

    model.output_buffer.comm.type = ENETSTL_OUTPUT_LAYER;
    model.output_buffer.comm.next_layer_off = 0;
    fprintf(stdout, "model size %llu", sizeof(model));
     fprintf(stdout,"output layer type %d", model.fc_out.comm.type);
     fprintf(stdout,"output layer off %d", model.fc_out.comm.next_layer_off);
    if (bpf_map_update_elem(bpf_map__fd(skel->maps.model_map), &key0, &model, BPF_ANY) < 0)
    {
        perror("update model_map");
        return -1;
    }

    // 2) input_map[0] 置零
    int zeros[6] = {0};
    if (bpf_map_update_elem(bpf_map__fd(skel->maps.input_map), &key0, zeros, BPF_ANY) < 0)
    {
        perror("update input_map");
        return -1;
    }
    return 0;
}

/* ====== 跑完后读回 output_buffer，打印结果 ====== */
static int check_after_run(void *opaque_skel, int run_res, int prog_retval)
{
    (void)run_res;
    (void)prog_retval;
    struct simdnn_bpf *skel = opaque_skel;

    __u32 key0 = 0;
    struct model out = {};
    if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.model_map), &key0, &out) < 0)
    {
        perror("lookup model_map");
        return -1;
    }
    int y0 = out.output_buffer.buffer[0];
    int y1 = (N3 > 1) ? out.output_buffer.buffer[1] : 0;
    int pred = (y0 >= y1) ? 0 : 1;

    printf("Inference output: y0=%d, y1=%d, pred=%d\n", y0, y1, pred);

    if (y0 == 0 && y1 == 0)
        fprintf(stderr, "WARN: outputs are zero; 请确认 eBPF 侧 bpf_nm_inference 的 attr_size 传参为 6*sizeof(int)。\n");
    return 0;
}

int main(void)
{
    /* 补齐 5-tuple。
       端口/目的 IP 随意但要“固定”，这样状态会累计到同一 flow 上。 */
    struct ipv4_packet pkt = pkt_v4;
    pkt.iph.tot_len = __bpf_constant_htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    pkt.iph.saddr = htonl(0x0a000001); // 10.0.0.1
    pkt.iph.daddr = htonl(0x0a000002); // 10.0.0.2
    pkt.tcph.source = __bpf_constant_htons(12345);
    pkt.tcph.dest = __bpf_constant_htons(8080);
    pkt.tcph.fin = 0;
    pkt.tcph.rst = 0;

#ifndef REPEAT
#define REPEAT 1
#endif

    BPF_PROG_TEST_RUNNER_WITH_CALLBACK(
        "test_xdp_simdnn_infer",
        simdnn_bpf,
        pkt,
        xdp_main,
        REPEAT,                 // 判断阈值
        setup_maps_before_load, // before_load
        setup_maps_after_load,  // after_load：初始化 model_map / input_map
        check_after_run,        // after_run：读取 output_buffer
        XDP_PASS)
}
