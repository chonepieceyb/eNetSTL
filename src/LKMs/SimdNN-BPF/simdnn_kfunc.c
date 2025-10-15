#include "../../src/bpf_kern/SimdNN-BPF/common.h"

// analyze the neural network structure
int simdnn_analyze_and_infer(void *m, int *attr)
{
    /* 临时缓冲区 */
    int tmp_in[64] = {0};
    int tmp_out[64] = {0};

    struct layer_common *layer;
    int offset = 0;

    layer = (struct layer_common *)(m + offset);
    if (layer->type != ENETSTL_FC_LAYER)
    {
        // 第一层必须是全连接层
        return -1;
    }

    // 取出输入缓冲区中的输入
    struct fc_layer *fc = (struct fc_layer *)layer;
    int in = fc->parm.in_features;
    int out = fc->parm.out_features;
    memcpy(tmp_in, attr, in * sizeof(tmp_in[0]));

    // TODO: 读取fc->weight[out][in]和fc->bias[out]和attr[in]进行矩阵相乘，使用simd并行计算
    while (1)
    {
        if (layer->next_layer_off == 0)
        {
            //tmp_out 保存最终输出到modle->output_buffer
            // No more layers 也是最终的输出层，保存结果
            break;
        }
        if (layer->type == ENETSTL_FC_LAYER)
        {
            tmp_out = {0};
            for (int i = 0; i < out; i++)
            {
                for (int j = 0; j < in; j++)
                {
                    // 这里进行矩阵乘法计算
                    // tmp_in[j] * fc->weights[i][j]
                    // 这里使用SIMD并行计算加速:tmp_out[i] += tmp_in[j] * fc->weights[i][j];
                }
            }
        }
        else if (layer->type == ENETSTL_RELU_LAYER)
        {
            tmp_out = {0};
            // Relu激活函数
            continue;
        }
        else
        {
            return -1;
        }
        offset += layer->next_layer_off;
        layer = (struct layer_common *)(m + offset);
        fc = (struct fc_layer *)layer;
        in = fc->parm.in_features;
        out = fc->parm.out_features;
        tmp_in = {0};
        memcpy(tmp_in, tmp_out, in * sizeof(tmp_in[0]));
    }
    return 0;
}

/* kfunc for inference */
__bpf_kfunc_start_defs();

__bpf_kfunc int bpf_nm_inference(void *model, int model_size__sz, void *attr, int attr__sz)
{
    return 0;
}

__bpf_kfunc_end_defs();