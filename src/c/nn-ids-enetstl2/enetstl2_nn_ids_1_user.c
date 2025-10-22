#include "../config.h"
#include "../common.h"
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <netinet/tcp.h>
#include <bpf/bpf_endian.h>
#include "../bpf_skel/enetstl2_nn_ids_1.skel.h"                  // skeleton（包含 xdp_simdnn_main 和各 maps）
#include "../../bpf_kern/nn-ids-enetstl/mlp_params.bpf.h" // N0..N3 和 layer_* 权重（与内核侧一致）
#include "common_user.h"                                  // layer_common、layer_fc、layer_relu、model



struct model1 {
    struct fc_layer     fc1;
    struct relu_layer   relu1;
    struct fc_layer     fc2;
    struct relu_layer   relu2;
    struct fc_layer     fc_out;
    struct output_layer output_buffer;
};

static int callback_before_load(void *skel)
{
	/* clear pinned maps */
	remove("/sys/fs/bpf/flow_map");
    	remove("/sys/fs/bpf/model_map");
	return 0;
}

static int empty_callback_after_attach(void *skel)
{
	return 0;
}

typedef struct model1 nn_model;

static int callback_after_load(void *__skel)
{
	struct enetstl2_nn_ids_1 *skel = __skel;
	__u32 key0 = 0;
	nn_model model = (nn_model){0};

	/* fc1: N0 -> N1 */
	model.fc1.comm.type = ENETSTL_FC_LAYER;
	model.fc1.comm.next_layer_off = (int)offsetof(nn_model, relu1);
	model.fc1.parm.in_features = N0;
	model.fc1.parm.out_features = N1;
	for (int i = 0; i < N1; i++)
	{
		for (int j = 0; j < N0; j++)
		model.fc1.weights[i][j] = layer_0_weight[i * N0 + j];
	}

	/* relu1 -> fc2 */
	model.relu1.comm.type = ENETSTL_RELU_LAYER;
	model.relu1.comm.next_layer_off = (int)offsetof(nn_model, fc2);
	model.relu1.feature_num = N1;

	/* fc2: N1 -> N2 */
	model.fc2.comm.type = ENETSTL_FC_LAYER;
	model.fc2.comm.next_layer_off = (int)offsetof(nn_model, relu2);
	model.fc2.parm.in_features = N1;
	model.fc2.parm.out_features = N2;
	for (int i = 0; i < N2; i++)
	{
		for (int j = 0; j < N1; j++)
		model.fc2.weights[i][j] = layer_1_weight[i * N1 + j];
	}

	model.relu2.comm.type = ENETSTL_RELU_LAYER;
	model.relu2.comm.next_layer_off = (int)offsetof(nn_model, fc_out);  /* set to next hidden layer or output, here is fc_out*/
	model.relu2.feature_num = N2;

	model.fc_out.comm.type = ENETSTL_FC_LAYER;
	model.fc_out.comm.next_layer_off = (int)offsetof(nn_model, output_buffer);
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
	return 0;
}

int main(int argc, char **argv)
{
    BPF_XDP_SKEL_LOADER_WITH_CALLBACKS(enetstl2_nn_ids_1, XDP_IF, xdp_main,
		callback_before_load,
                callback_after_load,
		empty_callback_after_attach,
			    XDP_MODE)
}