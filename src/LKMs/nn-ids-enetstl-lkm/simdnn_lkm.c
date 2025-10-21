// // simdnn_lkm.c
// // SPDX-License-Identifier: GPL-2.0
// #include "common.h"
// #include <linux/string.h>
// #include <linux/kernel.h>
// #include <asm/fpu/api.h>
// #include "nn-ids-enetstl-lkm.h"

// #if defined(__x86_64__) || defined(__i386__)
// #include <asm/simd.h>
// #include <linux/sched.h>
// #endif

// /* 直接推理函数，将模型直接写入内核 */
// int simdnn_infer(void *input_buffer, int input_buffer_size)
// {
// 	// 创建模型
// 	struct model model = (struct model){0};

// 	/* fc1: N0 -> N1 */
// 	model.fc1.comm.type = ENETSTL_FC_LAYER;
// 	model.fc1.comm.next_layer_off = (int)offsetof(struct model, relu1);
// 	model.fc1.parm.in_features = N0;
// 	model.fc1.parm.out_features = N1;
// 	for (int i = 0; i < N1; i++)
// 	{
// 		for (int j = 0; j < N0; j++)
// 			model.fc1.weights[i][j] = layer_0_weight[i * N0 + j];
// 	}

// 	/* relu1 -> fc2 */
// 	model.relu1.comm.type = ENETSTL_RELU_LAYER;
// 	model.relu1.comm.next_layer_off = (int)offsetof(struct model, fc2);

// 	/* fc2: N1 -> N2 */
// 	model.fc2.comm.type = ENETSTL_FC_LAYER;
// 	model.fc2.comm.next_layer_off = (int)offsetof(struct model, relu2);
// 	model.fc2.parm.in_features = N1;
// 	model.fc2.parm.out_features = N2;
// 	for (int i = 0; i < N2; i++)
// 	{
// 		for (int j = 0; j < N1; j++)
// 			model.fc2.weights[i][j] = layer_1_weight[i * N1 + j];
// 	}

// 	/* relu2 -> fc_out -> output_buffer(终止) */
// 	model.relu2.comm.type = ENETSTL_RELU_LAYER;
// 	model.relu2.comm.next_layer_off = (int)offsetof(struct model, fc_out);

// 	model.fc_out.comm.type = ENETSTL_FC_LAYER;
// 	model.fc_out.comm.next_layer_off = (int)offsetof(struct model, output_buffer);
// 	model.fc_out.parm.in_features = N2;
// 	model.fc_out.parm.out_features = N3;
// 	for (int i = 0; i < N3; i++)
// 	{
// 		for (int j = 0; j < N2; j++)
// 			model.fc_out.weights[i][j] = layer_2_weight[i * N2 + j];
// 	}

// 	model.output_buffer.comm.type = ENETSTL_OUTPUT_LAYER;
// 	model.output_buffer.comm.next_layer_off = 0;

// 	// 双缓冲区
// 	int idx = 0;
// 	int bufs[2][64] = {0};
// 	int *cur_in_buf = (int *)&bufs[idx & 1];
// 	int *cur_out_buf = (int *)&bufs[(idx + 1) & 1];

// 	// 初始化输入
// 	memcpy(cur_in_buf, input_buffer, input_buffer_size);

// 	// 构造好模型以后，调用内核函数逐层进行推理
// 	struct layer_common *layer = (struct layer_common *)&model;

// 	// FC1
// 	fc_forward_i32((const struct fc_layer *)layer, cur_in_buf, N0 * sizeof(int), cur_out_buf, N1 * sizeof(int));
// 	layer = (struct layer_common *)((void *)layer + layer->next_layer_off);

	
// 	// ReLU1
// 	relu_inplace_i32(cur_out_buf, N1);


// };