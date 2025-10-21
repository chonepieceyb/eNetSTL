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
static inline void relu_inplace_i32(int *v, int n)
{
	for (int i = 0; i < n; ++i)
		if (v[i] < 0)
			v[i] = 0;
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
static int fc_forward_i32(const struct fc_layer *fc,
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

		/* 饱和写回 */
		if (acc0 > INT_MAX)
			acc0 = INT_MAX;
		else if (acc0 < INT_MIN)
			acc0 = INT_MIN;
		if (acc1 > INT_MAX)
			acc1 = INT_MAX;
		else if (acc1 < INT_MIN)
			acc1 = INT_MIN;
		y[o + 0] = (int)(acc0 >> 16);
		y[o + 1] = (int)(acc1 >> 16);
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

		if (acc > INT_MAX)
			acc = INT_MAX;
		else if (acc < INT_MIN)
			acc = INT_MIN;
		y[o] = (int)(acc >> 16);
	}

	return out;

#else /* --------- 无 AVX2：保持 64 位标量安全路径 --------- */

	for (int o = 0; o < out; ++o)
	{
		const int *row = fc->weights[o];
		long long acc = 0;
		for (int j = 0; j < in; ++j)
			acc += (long long)row[j] * (long long)x[j];
		if (acc > INT_MAX)
			acc = INT_MAX;
		else if (acc < INT_MIN)
			acc = INT_MIN;
		y[o] = (int)(acc >> 16);
	}
	return out;

#endif
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
	if (!m || !attr)
		return -EINVAL;
	if (model_size <= 0)
		return -EINVAL;
	if (attr_size <= 0 || (attr_size % sizeof(int)) != 0)
		return -EINVAL;

	int tmp_in[64] = {0}; /* 与权重上限 64 对齐 */
	int tmp_out[64] = {0};
	int attr_words = attr_size / (int)sizeof(int);

	int offset = 0;
	struct layer_common *layer =
		(struct layer_common *)((char *)m + offset);

	/* 第一层必须是 FC */
	if (layer->type != ENETSTL_FC_LAYER)
		return -EINVAL;

	/* 准备首层输入：从 attr 拷贝 in_features 个元素 */
	struct fc_layer *fc = (struct fc_layer *)layer;
	int in = fc->parm.in_features;
	int out = fc->parm.out_features;

	if (in <= 0 || in > (int)ARRAY_SIZE(tmp_in))
		return -EMSGSIZE;
	if (attr_words < in)
		return -EMSGSIZE;
	memcpy(tmp_in, attr, in * sizeof(tmp_in[0]));

	/* 进入 FPU/SIMD 临界区 */
	kernel_fpu_begin();

	int cur_len = in;

	const char *p_history;

	while (1)
	{
		const char *base = (const char *)m;
		const char *p = (const char *)layer;
		p_history = p;

		size_t total = (size_t)model_size; /* 模型总字节数 */
		size_t off = (size_t)offset;	   /* 本层起点 */
		int nli = layer->next_layer_off;
		size_t layer_size;

		/* 基本地址先验：layer 起点必须在 blob 内 */
		if (p < base || p >= base + total)
		{
			kernel_fpu_end();
			return -EFAULT;
		}

		/* 由 next_layer_off(绝对偏移) 推算 layer_size */
		if (nli < 0)
		{
			kernel_fpu_end();
			return -EFAULT;
		}
		else if (nli == 0)
		{
			/* 最后一层：占用剩余 */
			if (off > total)
			{ /* 防御：offset 合法性 */
				kernel_fpu_end();
				return -EFAULT;
			}
			layer_size = total - off;
		}
		else
		{
			size_t nloff = (size_t)nli; /* 下一层绝对偏移 */
			if (nloff < off || nloff > total)
			{ /* 单调且不越界 */
				kernel_fpu_end();
				return -EFAULT;
			}
			layer_size = nloff - off;
		}

		/* 区间完全包含检查：[p, p+layer_size) ⊆ [base, base+total)。
		   用“不相加式”判断避免 p+layer_size 溢出： */
		{
			size_t start_off = (size_t)(p - base); /* p>=base 已保证 */
			if (!(start_off <= total && layer_size <= total - start_off))
			{
				kernel_fpu_end();
				return -EFAULT;
			}
		}

		if (layer->type == ENETSTL_FC_LAYER)
		{
			fc = (struct fc_layer *)layer;
			in = fc->parm.in_features;
			out = fc->parm.out_features;

			if (cur_len != in || out > (int)ARRAY_SIZE(tmp_out))
			{
				kernel_fpu_end();
				return -EINVAL;
			}

			memset(tmp_out, 0, sizeof(tmp_out));
			int ret = fc_forward_i32(fc,
									 tmp_in, ARRAY_SIZE(tmp_in),
									 tmp_out, ARRAY_SIZE(tmp_out));
			if (ret < 0)
			{
				kernel_fpu_end();
				return ret;
			}
			cur_len = ret; /* = out */
			memcpy(tmp_in, tmp_out, cur_len * sizeof(tmp_in[0]));
		}
		else if (layer->type == ENETSTL_RELU_LAYER)
		{
			if (cur_len <= 0 || cur_len > (int)ARRAY_SIZE(tmp_in))
			{
				kernel_fpu_end();
				return -EINVAL;
			}
			relu_inplace_i32(tmp_in, cur_len);
		}
		else
		{
			kernel_fpu_end();
			return -EOPNOTSUPP; /* 只支持 FC/RELU */
		}

		/* 0 => 没有下一层，退出 */
		if (layer->next_layer_off == 0)
			break;

		/* 推进到下一层并检查越界 */
		if (layer->next_layer_off < 0 ||
			offset + layer->next_layer_off >= model_size)
		{
			kernel_fpu_end();
			return -EFAULT;
		}
		offset = layer->next_layer_off;
		layer = (struct layer_common *)((char *)m + offset);
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
