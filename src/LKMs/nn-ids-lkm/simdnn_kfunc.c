// simdnn_kfunc.c
// SPDX-License-Identifier: GPL-2.0
#include "common.h"
#include <linux/string.h>
#include <linux/kernel.h>
#include <asm/fpu/api.h>
#include "nn-ids-enetstl-lkm.h"

#if defined(__x86_64__) || defined(__i386__)
#include <asm/simd.h>
#include <linux/sched.h>
#endif

/* ===================== 工具函数 ===================== */

/* ReLU */

void relu_inplace_i32(int *v, int n)
{

#ifdef __AVX2__
	int i = 0;
	const __m256i z = _mm256_setzero_si256();
	for (; i + 8 <= n; i += 8)
	{
		__m256i x = _mm256_loadu_si256((const __m256i *)(v + i));
		__m256i y = _mm256_max_epi32(x, z); // ReLU
		_mm256_storeu_si256((__m256i *)(v + i), y);
	}
	for (; i < n; ++i)
	{
		if (v[i] < 0)
			v[i] = 0;
	}
#else
	for (int i = 0; i < n; ++i)
	{
		if (v[i] < 0)
			v[i] = 0;
	}
#endif
}

/* ---- AVX2: 4x i64 水平求和，不落内存 ---- */
#ifdef __AVX2__
static inline long long hsum_epi64_avx2(__m256i v)
{
	__m128i lo = _mm256_castsi256_si128(v);
	__m128i hi = _mm256_extracti128_si256(v, 1);
	__m128i s = _mm_add_epi64(lo, hi);			// [a+c, b+d]
	s = _mm_add_epi64(s, _mm_srli_si128(s, 8)); // s0 += s1
	return (long long)_mm_cvtsi128_si64(s);
}
#endif

/* FC: y = W * x，64 位安全乘加；AVX2: 双行并行 + 复用 x 加载 */
int fc_forward_i32(const struct fc_layer *fc,
						  const int *x, int x_cap,
						  int *y, int y_cap)
{
	const int in = fc->parm.in_features;
	const int out = fc->parm.out_features;

	if (in <= 0 || out <= 0)
		return -EINVAL;
	if (in > x_cap || out > y_cap)
		return -EMSGSIZE;

#if defined(__AVX2__)
	int o = 0;

	/* ---- 主循环：两行一组，复用同一批 x 向量加载 ---- */
	for (; o + 1 < out; o += 2)
	{
		const int *row0 = fc->weights[o + 0];
		const int *row1 = fc->weights[o + 1];

		__m256i vsum0 = _mm256_setzero_si256(); // 行 o 局部和（4x i64）
		__m256i vsum1 = _mm256_setzero_si256(); // 行 o+1 局部和（4x i64）
		int j = 0;

		for (; j + 8 <= in; j += 8)
		{
			// 只加载一次 x
			__m256i vx = _mm256_loadu_si256((const __m256i *)(x + j)); // 8x i32
			__m256i vx_odd = _mm256_srli_epi64(vx, 32);

			// 行 o
			__m256i va0 = _mm256_loadu_si256((const __m256i *)(row0 + j));		   // 8x i32
			__m256i p0_even = _mm256_mul_epi32(va0, vx);						   // 0,2,4,6 : 32x32->64
			__m256i p0_odd = _mm256_mul_epi32(_mm256_srli_epi64(va0, 32), vx_odd); // 1,3,5,7
			vsum0 = _mm256_add_epi64(vsum0, p0_even);
			vsum0 = _mm256_add_epi64(vsum0, p0_odd);

			// 行 o+1
			__m256i va1 = _mm256_loadu_si256((const __m256i *)(row1 + j));
			__m256i p1_even = _mm256_mul_epi32(va1, vx);
			__m256i p1_odd = _mm256_mul_epi32(_mm256_srli_epi64(va1, 32), vx_odd);
			vsum1 = _mm256_add_epi64(vsum1, p1_even);
			vsum1 = _mm256_add_epi64(vsum1, p1_odd);
		}

		/* 寄存器水平归约 → 标量累加 */
		long long acc0 = hsum_epi64_avx2(vsum0);
		long long acc1 = hsum_epi64_avx2(vsum1);

		/* 尾巴（<8）标量补齐，仍保持 64 位安全乘加 */
		for (; j < in; ++j)
		{
			long long xv = (long long)x[j];
			acc0 += (long long)row0[j] * xv;
			acc1 += (long long)row1[j] * xv;
		}

		y[o + 0] = acc0 >> 16;
		y[o + 1] = acc1 >> 16;
	}

	/* ---- 剩余一行 ---- */
	for (; o < out; ++o)
	{
		const int *row = fc->weights[o];
		__m256i vsum = _mm256_setzero_si256();
		int j = 0;

		for (; j + 8 <= in; j += 8)
		{
			// 只加载一次 x
			__m256i vx = _mm256_loadu_si256((const __m256i *)(x + j)); // 8x i32
			__m256i vx_odd = _mm256_srli_epi64(vx, 32);

			// 行 o
			__m256i va = _mm256_loadu_si256((const __m256i *)(row + j));		 // 8x i32
			__m256i p_even = _mm256_mul_epi32(va, vx);							 // 0,2,4,6 : 32x32->64
			__m256i p_odd = _mm256_mul_epi32(_mm256_srli_epi64(va, 32), vx_odd); // 1,3,5,7
			vsum = _mm256_add_epi64(vsum, p_even);
			vsum = _mm256_add_epi64(vsum, p_odd);
		}

		long long acc = hsum_epi64_avx2(vsum);
		for (; j < in; ++j)
			acc += (long long)row[j] * (long long)x[j];

		y[o] = (int)(acc >> 16);
	}

	return 0;

#else /* --------- 无 AVX2：保持 64 位标量安全路径 --------- */

	for (int o = 0; o < out; ++o)
	{
		const int *row = fc->weights[o];
		long long acc = 0;
		for (int j = 0; j < in; ++j)
			acc += (long long)row[j] * (long long)x[j];
		y[o] = (int)(acc >> 16);
	}
	return 0;

#endif
}

static inline size_t get_layer_size(struct layer_common *comm)
{
	switch (comm->type)
	{
	case ENETSTL_FC_LAYER:
		return sizeof(struct fc_layer);
	case ENETSTL_RELU_LAYER:
		return sizeof(struct relu_layer);
	case ENETSTL_OUTPUT_LAYER:
		return sizeof(struct output_layer);
	default:
		return 0;
	}
}

/* ===================== 主流程（层遍历） ===================== */
/* m:           模型/网络 blob 起始地址（struct model*）
 * model_size:  模型 blob 字节大小（越界保护）
 * attr:        输入缓冲（以 int* 解释）
 * attr_size:   输入缓冲字节数
 * 返回：最终输出维度（>0）或负错
 */
int simdnn_analyze_and_infer(void *m, size_t model_size, void *attr, size_t attr_size)
{
	int iter_idx = 0;
	int buf1[64] = {0};
	int buf2[64] = {0};
	int *bufs[2] = {&buf1[0], &buf2[0]};

	int *curr_in_buf = (int *)(bufs[iter_idx & 1]);
	int *curr_out_buf = (int *)(bufs[(iter_idx + 1) & 1]);

	int err = 0;
	if (attr_size > sizeof(buf1) || model_size <= sizeof(struct layer_common))
	{
		// attr too large
		return -EINVAL;
	}
	// if (in <= 0 || in > (int)ARRAY_SIZE(tmp_in))
	// 	return -EMSGSIZE;
	// if (attr_words < in)
	// 	return -EMSGSIZE;
	memcpy(curr_in_buf, attr, attr_size);

	struct layer_common *curr_layer = (struct layer_common *)m;

	/* 进入 FPU/SIMD 临界区 */
	kernel_fpu_begin();

	while (1)
	{
		size_t layer_size = get_layer_size(curr_layer);
		if ((void *)curr_layer + layer_size > m + model_size)
		{
			err = -EFAULT;
			goto error;
		}
		if (curr_layer->type == ENETSTL_FC_LAYER)
		{
			struct fc_layer *fc = (struct fc_layer *)curr_layer;
			int ret = fc_forward_i32(fc,
									 curr_in_buf, ARRAY_SIZE(buf1),
									 curr_out_buf, ARRAY_SIZE(buf1));
			if (ret < 0)
			{
				err = -EINVAL;
				goto error;
			}
		}
		else if (curr_layer->type == ENETSTL_RELU_LAYER)
		{
			struct relu_layer *rl = (struct relu_layer *)curr_layer;
			relu_inplace_i32(curr_in_buf, min(sizeof(buf1), (size_t)(rl->feature_num)));
		}
		else if (curr_layer->type == ENETSTL_OUTPUT_LAYER)
		{
			goto output;
		}
		else
		{
			err = -EOPNOTSUPP;
			goto error;
		}

		iter_idx += 1;
		curr_in_buf = bufs[iter_idx & 1];
		curr_out_buf = bufs[(iter_idx + 1) & 1];
		memset(curr_out_buf, 0, sizeof(buf1));
		curr_layer = (struct layer_common *)(m + curr_layer->next_layer_off);
	}

output:;
	kernel_fpu_end();
	struct output_layer *out = (struct output_layer *)(curr_layer);
	memcpy(&out->buffer, curr_out_buf, min(sizeof(buf1), sizeof(out->buffer)));
	return iter_idx;
error:;
	kernel_fpu_end();
	return err;
}