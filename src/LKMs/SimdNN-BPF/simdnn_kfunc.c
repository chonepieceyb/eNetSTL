// simdnn_kfunc.c
// SPDX-License-Identifier: GPL-2.0
#include "common.h"
#include <linux/string.h>
#include <linux/kernel.h>
#include <asm/fpu/api.h>

#if defined(__x86_64__) || defined(__i386__)
  // #include <immintrin.h> 
#endif

/* ===================== 工具函数 ===================== */

/* ReLU */
static inline void relu_inplace_i32(int *v, int n)
{
	for (int i = 0; i < n; ++i)
		if (v[i] < 0) v[i] = 0;
}

/* FC: y = W * x
 * - W 行主序：weights[out][in]；无 bias（按 common.h）
 * - 为避免溢出，用 s64 累加，回写时饱和到 int32
 * - AVX2 快路径 + 标量回退
 */
static int fc_forward_i32(const struct fc_layer *fc,
                          const int *x, int x_cap,
                          int *y, int y_cap)
{
	const int in  = fc->parm.in_features;
	const int out = fc->parm.out_features;

	if (in <= 0 || out <= 0)            return -EINVAL;
	if (in > x_cap || out > y_cap)      return -EMSGSIZE;

	for (int o = 0; o < out; ++o) {
		const int *row = fc->weights[o];
		long long acc = 0;  /* s64 */

#if defined(__AVX2__)
		int j = 0;
		__m256i vsum = _mm256_setzero_si256();
		for (; j + 8 <= in; j += 8) {
			__m256i va = _mm256_loadu_si256((const __m256i*)(row + j)); /* vmovdqu */
			__m256i vb = _mm256_loadu_si256((const __m256i*)(x   + j)); /* vmovdqu */
			__m256i vm = _mm256_mullo_epi32(va, vb);                    /* vpmulld */
			vsum = _mm256_add_epi32(vsum, vm);
		}
		if (in >= 8) {
			alignas(32) int buf[8];
			_mm256_store_si256((__m256i*)buf, vsum);
#pragma unroll
			for (int k = 0; k < 8; ++k) acc += (long long)buf[k];
		}
		for (; j < in; ++j)
			acc += (long long)row[j] * (long long)x[j];
#else
		for (int j = 0; j < in; ++j)
			acc += (long long)row[j] * (long long)x[j];
#endif

		if (acc > INT_MAX) acc = INT_MAX;
		if (acc < INT_MIN) acc = INT_MIN;
		y[o] = (int)acc;
	}
	return out;
}

/* ===================== 主流程（层遍历） ===================== */
/* m:           模型/网络 blob 起始地址（struct model*）
 * model_size:  模型 blob 字节大小（越界保护）
 * attr:        输入缓冲（以 int* 解释）
 * attr_size:   输入缓冲字节数
 * 返回：最终输出维度（>0）或负错
 */
int simdnn_analyze_and_infer(void *m, int model_size, int *attr, int attr_size)
{
	if (!m || !attr)                      return -EINVAL;
	if (model_size <= 0)                  return -EINVAL;
	if (attr_size <= 0 || (attr_size % sizeof(int)) != 0)
		return -EINVAL;

	int tmp_in[64]  = {0};   /* 与权重上限 64 对齐 */
	int tmp_out[64] = {0};
	int attr_words  = attr_size / (int)sizeof(int);

	int offset = 0;
	struct layer_common *layer =
		(struct layer_common *)((char*)m + offset);

	/* 第一层必须是 FC */
	if (layer->type != ENETSTL_FC_LAYER)
		return -EINVAL;

	/* 准备首层输入：从 attr 拷贝 in_features 个元素 */
	struct fc_layer *fc = (struct fc_layer *)layer;
	int in  = fc->parm.in_features;
	int out = fc->parm.out_features;

	if (in <= 0 || in > (int)ARRAY_SIZE(tmp_in)) return -EMSGSIZE;
	if (attr_words < in)                         return -EMSGSIZE;
	memcpy(tmp_in, attr, in * sizeof(tmp_in[0]));

	/* 进入 FPU/SIMD 临界区（官方建议：尽量缩小范围） */
	kernel_fpu_begin(); /* 仅在可用且合适的上下文调用。:contentReference[oaicite:1]{index=1} */

	int cur_len = in;

	while (1) {
		/* layer 必须位于模型 blob 内 */
		if ((char*)layer < (char*)m ||
		    (char*)layer >= (char*)m + model_size) {
			kernel_fpu_end();
			return -EFAULT;
		}

		if (layer->type == ENETSTL_FC_LAYER) {
			fc  = (struct fc_layer *)layer;
			in  = fc->parm.in_features;
			out = fc->parm.out_features;

			if (cur_len != in || out > (int)ARRAY_SIZE(tmp_out)) {
				kernel_fpu_end();
				return -EINVAL;
			}

			memset(tmp_out, 0, sizeof(tmp_out));
			int ret = fc_forward_i32(fc,
			                         tmp_in,  ARRAY_SIZE(tmp_in),
			                         tmp_out, ARRAY_SIZE(tmp_out));
			if (ret < 0) {
				kernel_fpu_end();
				return ret;
			}
			cur_len = ret; /* = out */
			memcpy(tmp_in, tmp_out, cur_len * sizeof(tmp_in[0]));

		} else if (layer->type == ENETSTL_RELU_LAYER) {
			if (cur_len <= 0 || cur_len > (int)ARRAY_SIZE(tmp_in)) {
				kernel_fpu_end();
				return -EINVAL;
			}
			relu_inplace_i32(tmp_in, cur_len);

		} else {
			kernel_fpu_end();
			return -EOPNOTSUPP; /* 只支持 FC/RELU */
		}

		/* 0 => 没有下一层，退出 */
		if (layer->next_layer_off == 0)
			break;

		/* 推进到下一层并检查越界 */
		if (layer->next_layer_off < 0 ||
		    offset + layer->next_layer_off >= model_size) {
			kernel_fpu_end();
			return -EFAULT;
		}
		offset += layer->next_layer_off;
		layer = (struct layer_common *)((char*)m + offset);
	}

	kernel_fpu_end();

	/* 仅把最终结果写入 model->output_buffer.buffer，供 BPF 端读取 */
	{
		struct model *mdl = (struct model *)m;
		size_t max_out = ARRAY_SIZE(mdl->output_buffer.buffer); /* N3 in common.h */
		size_t to_copy = min_t(size_t, (size_t)cur_len, max_out);
		if (to_copy > 0)
			memcpy(mdl->output_buffer.buffer, tmp_in, to_copy * sizeof(int));
	}

	return cur_len;
}

/* ===================== kfunc for eBPF ===================== */
#include <linux/btf.h>
#include <linux/bpf.h>


/* 语义：
 *   model:          模型起始地址（BTF 类型经 verifier 约束后可安全传递）
 *   model_size__sz: 模型大小（字节）
 *   attr:           输入特征首地址（以 int* 解释）
 *   attr_size__sz:  输入特征大小（字节）
 * 返回：最终输出维度（>0），负值为错误码
 */
__bpf_kfunc int bpf_nm_inference(void *model, int model_size__sz,
                                 void *attr,  int attr_size__sz)
{
	if (!model || !attr)                               return -EINVAL;
	if (model_size__sz <= 0)                           return -EINVAL;
	if (attr_size__sz <= 0 || (attr_size__sz % sizeof(int)) != 0)
		return -EINVAL;

	/* 只写回 model->output_buffer，让 BPF 端直接读取它 */
	return simdnn_analyze_and_infer(model, model_size__sz,
	                                (int *)attr, attr_size__sz);
}

