#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/simd.h>
#include <asm/simd.h>
#include <immintrin.h>
#include "../../bpf_kern/SimdNN-BPF/common.h"
#include "../../bpf_kern/SimdNN-BPF/mlp_params.bpf.h"

// Layer types
#define ENETSTL_FC_LAYER 1
#define ENETSTL_RELU_LAYER 2

// Forward declarations
static int simdnn_fc_layer_forward(struct fc_layer *layer, int *input, int *output);
static int simdnn_relu_layer_forward(struct relu_layer *layer, int *input, int *output);
static void simdnn_simd_fc_forward(const int *weights, const int *bias, const int *input,
                                  int *output, int in_features, int out_features);

// Neural network inference kfunc
__bpf_kfunc int bpf_nm_inference(void *model, int model_size)
{
    struct model *m = (struct model *)model;
    int temp_buffer1[32] = {0};
    int temp_buffer2[32] = {0};
    int *current_input, *current_output;
    int ret = 0;

    if (!m || model_size < sizeof(struct model)) {
        pr_err("Invalid model parameters\n");
        return -EINVAL;
    }

    // Enable SIMD
    kernel_fpu_begin();

    // Start with input buffer
    current_input = m->input_buffer;
    current_output = temp_buffer1;

    // Layer 1: FC -> ReLU
    ret = simdnn_fc_layer_forward(&m->fc1, current_input, current_output);
    if (ret) {
        pr_err("FC layer 1 forward failed\n");
        goto out;
    }

    // ReLU activation
    current_input = current_output;
    current_output = temp_buffer2;
    ret = simdnn_relu_layer_forward(&m->relu1, current_input, current_output);
    if (ret) {
        pr_err("ReLU layer 1 forward failed\n");
        goto out;
    }

    // Layer 2: FC -> ReLU
    current_input = current_output;
    current_output = temp_buffer1;
    ret = simdnn_fc_layer_forward(&m->fc2, current_input, current_output);
    if (ret) {
        pr_err("FC layer 2 forward failed\n");
        goto out;
    }

    // ReLU activation
    current_input = current_output;
    current_output = temp_buffer2;
    ret = simdnn_relu_layer_forward(&m->relu2, current_input, current_output);
    if (ret) {
        pr_err("ReLU layer 2 forward failed\n");
        goto out;
    }

    // Output layer: FC
    current_input = current_output;
    current_output = m->output_buffer;
    ret = simdnn_fc_layer_forward(&m->output, current_input, current_output);
    if (ret) {
        pr_err("Output FC layer forward failed\n");
        goto out;
    }

    ret = 0;

out:
    kernel_fpu_end();
    return ret;
}
EXPORT_SYMBOL_GPL(bpf_nm_inference);

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

// BTF kfunc registration
BTF_SET8_START(simdnn_kfunc_list)
BTF_ID_FLAGS(func, bpf_nm_inference, KF_TRUSTED_ARGS)
BTF_SET8_END(simdnn_kfunc_list)

static const struct btf_kfunc_id_set simdnn_kfunc_set = {
    .owner = THIS_MODULE,
    .set   = &simdnn_kfunc_list,
};

static int __init simdnn_init(void)
{
    int ret;

    pr_info("SimdNN-BPF kfunc module loading\n");

    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &simdnn_kfunc_set);
    if (ret) {
        pr_err("Failed to register SimdNN kfuncs: %d\n", ret);
        return ret;
    }

    pr_info("SimdNN-BPF kfunc module loaded successfully\n");
    return 0;
}

static void __exit simdnn_exit(void)
{
    pr_info("SimdNN-BPF kfunc module unloaded\n");
}

module_init(simdnn_init);
module_exit(simdnn_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("eNetSTL");
MODULE_DESCRIPTION("SimdNN-BPF kfunc implementation");
MODULE_VERSION("1.0");