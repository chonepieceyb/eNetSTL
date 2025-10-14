#include "../../src/bpf_kern/SimdNN-BPF/common.h"

// analyze the neural network structure
int analyze_nn_structure(void *nn_struct, int *layer_num, int *input_size, int *output_size)
{
    struct layer_common *layer;
    int offset = 0;
    int layer_count = 0;

    layer = (struct layer_common *)((char *)nn_struct + offset);
    if (layer->type != ENETSTL_FC_LAYER)
    {
        // The first layer must be a fully connected layer
        return -1;
    }

    // Get input size from the first fully connected layer
    struct fc_layer *fc = (struct fc_layer *)layer;
    *input_size = fc->parm.in_features;

    // Traverse the layers to count them and get output size
    while (1)
    {
        layer_count++;
        if (layer->next_layer_off == 0)
        {
            // No more layers
            break;
        }
        offset += layer->next_layer_off;
        layer = (struct layer_common *)((char *)nn_struct + offset);
        if (layer->type == ENETSTL_FC_LAYER)
        {
            fc = (struct fc_layer *)layer;
            *output_size = fc->parm.out_features;
        }
        else if (layer->type == ENETSTL_RELU_LAYER)
        {
            // ReLU layer does not change output size
            continue;
        }
        else
        {
            // Unknown layer type
            return -1;
        }
    }

    *layer_num = layer_count;
    return 0;
}

/* kfunc for inference */
__bpf_kfunc_start_defs();

__bpf_kfunc void bpf_nm_inference(void *model, int model_size__sz, void *attr, int attr__sz)
{
    //将eBPF栈的输入拷贝到内核栈
    int input_buffer[attr__sz];
    memcpy(input_buffer, attr, attr__sz);
    return;
}

__bpf_kfunc_end_defs();