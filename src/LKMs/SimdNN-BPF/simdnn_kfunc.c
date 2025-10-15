#include "../../src/bpf_kern/SimdNN-BPF/common.h"

// analyze the neural network structure
int simdnn_analyze_and_infer(void *m, int *attr)
{
    struct layer_common *layer;
    int offset = 0;
    int layer_count = 0;

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

    //TODO: 读取fc->weight[out][in]和fc->bias[out]和attr[in]进行矩阵相乘，使用simd并行计算
        while (1)
        {
            layer_count++;
            if (layer->next_layer_off == 0)
            {
                // No more layers 也是最终的输出层，保存结果
                break;
            }
            offset += layer->next_layer_off;
            layer = (struct layer_common *)((char *)nn_struct + offset);
            if (layer->type == ENETSTL_FC_LAYER)
            {
                fc = (struct fc_layer *)layer;
            }
            else if (layer->type == ENETSTL_RELU_LAYER)
            {
                continue;
            }
            else
            {
                return -1;
            }
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