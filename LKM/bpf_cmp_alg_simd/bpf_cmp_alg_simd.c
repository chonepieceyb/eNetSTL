#include <asm-generic/int-ll64.h>
#include <linux/bitops.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>
#include <linux/printk.h>

// This macro is required to include <immintrin.h> in the kernel
#define _MM_MALLOC_H_INCLUDED
#include <immintrin.h>

extern int register_btf_kfunc_id_set(enum bpf_prog_type prog_type,
				     const struct btf_kfunc_id_set *kset);

#define _mm256_loadu_si256_optional(ptr)                                       \
	(u64)(ptr) & ((1 << 5) - 1) ? _mm256_loadu_si256((__m256i_u *)(ptr)) : \
				      (*(__m256i *)(ptr))

#define _mm_loadu_si128_optional(ptr)                                       \
	(u64)(ptr) & ((1 << 5) - 1) ? _mm_loadu_si128((__m128i_u *)(ptr)) : \
				      *(__m128i *)(ptr)

static inline u32 __find_mask_u32_avx(const u32 *arr, u32 val)
{
	__m256i arr_vec = _mm256_loadu_si256_optional(arr),
		val_vec = _mm256_set1_epi32(val);
	__m256i cmp = _mm256_cmpeq_epi32(arr_vec, val_vec);
	u32 mask = _mm256_movemask_epi8(cmp);
	return mask;
}

static inline u32 __find_mask_u16_avx(const u16 *arr, u16 val)
{
	__m256i arr_vec = _mm256_loadu_si256_optional((const __m256i_u *)arr),
		val_vec = _mm256_set1_epi16(val);
	__m256i cmp = _mm256_cmpeq_epi16(arr_vec, val_vec);
	u32 mask = _mm256_movemask_epi8(cmp);
	return mask;
}

static inline u16 __find_mask_u16_sse(const u16 *arr, u16 val)
{
	__m128i arr_vec = _mm_loadu_si128_optional((__m128i_u *)arr),
		val_vec = _mm_set1_epi16(val);
	__m128i cmp = _mm_cmpeq_epi16(arr_vec, val_vec);
	u16 mask = _mm_movemask_epi8(cmp);
	return mask;
}

__bpf_kfunc u32 bpf_find_u32_avx(const u32 *arr, u32 val)
{
	u32 mask = __find_mask_u32_avx(arr, val);
	return __tzcnt_u32(mask) >> 2;
}
EXPORT_SYMBOL_GPL(bpf_find_u32_avx);

__bpf_kfunc u32 bpf_find_u16_avx(const u16 *arr, u16 val)
{
	u32 mask = __find_mask_u16_avx(arr, val);
	return __tzcnt_u32(mask) >> 1;
}
EXPORT_SYMBOL_GPL(bpf_find_u16_avx);

__bpf_kfunc u32 bpf_find_u16_sse(const u16 *arr, u16 val)
{
	u16 mask = __find_mask_u16_sse(arr, val);
	return __tzcnt_u16(mask) >> 1;
}
EXPORT_SYMBOL_GPL(bpf_find_u16_sse);

__bpf_kfunc u32 bpf__find_mask_u32_avx(const u32 *arr, u32 val)
{
	return __find_mask_u32_avx(arr, val);
}
EXPORT_SYMBOL_GPL(bpf__find_mask_u32_avx);

__bpf_kfunc u32 bpf__find_mask_u16_avx(const u16 *arr, u16 val)
{
	return __find_mask_u16_avx(arr, val);
}
EXPORT_SYMBOL_GPL(bpf__find_mask_u16_avx);

__bpf_kfunc u32 bpf__find_mask_u16_sse(const u16 *arr, u16 val)
{
	return __find_mask_u16_sse(arr, val);
}
EXPORT_SYMBOL_GPL(bpf__find_mask_u16_sse);

__bpf_kfunc u32 bpf_find_mask_u32_avx(const u32 *arr, u32 val)
{
	u32 _mask = __find_mask_u32_avx(arr, val), mask = 0;
	int i;

	for (i = 0; i < 8; i++) {
		mask |= ((_mask >> (i << 2)) & 0x1) << i;
	}

	return mask;
}
EXPORT_SYMBOL_GPL(bpf_find_mask_u32_avx);

__bpf_kfunc u32 bpf_find_mask_u16_avx(const u16 *arr, u16 val)
{
	u32 _mask = __find_mask_u16_avx(arr, val), mask = 0;
	int i;

	for (i = 0; i < 16; i++) {
		mask |= ((_mask >> (i << 1)) & 0x1) << i;
	}

	return mask;
}
EXPORT_SYMBOL_GPL(bpf_find_mask_u16_avx);

__bpf_kfunc u32 bpf_find_mask_u16_sse(const u16 *arr, u16 val)
{
	u16 _mask = __find_mask_u16_sse(arr, val), mask = 0;
	int i;

	for (i = 0; i < 8; i++) {
		mask |= ((_mask >> (i << 1)) & 0x1) << i;
	}

	return mask;
}
EXPORT_SYMBOL_GPL(bpf_find_mask_u16_sse);

__bpf_kfunc u32 bpf_tzcnt_u32(u32 val)
{
	return __tzcnt_u32(val);
}
EXPORT_SYMBOL_GPL(bpf_tzcnt_u32);

__bpf_kfunc u16 bpf_tzcnt_u16(u16 val)
{
	return __tzcnt_u16(val);
}
EXPORT_SYMBOL_GPL(bpf_tzcnt_u16);

__bpf_kfunc u32 bpf_find_min_u16_sse(const u16 *arr)
{
	__m128i arr_vec = _mm_loadu_si128((__m128i_u *)arr);
	__m128i res = _mm_minpos_epu16(arr_vec);
	return _mm_extract_epi16(res, 1);
}
EXPORT_SYMBOL_GPL(bpf_find_min_u16_sse);

BTF_SET8_START(bpf_cmp_alg_simd_kfunc_ids)
BTF_ID_FLAGS(func, bpf_find_u32_avx)
BTF_ID_FLAGS(func, bpf_find_u16_avx)
BTF_ID_FLAGS(func, bpf_find_u16_sse)
BTF_ID_FLAGS(func, bpf__find_mask_u32_avx)
BTF_ID_FLAGS(func, bpf__find_mask_u16_avx)
BTF_ID_FLAGS(func, bpf__find_mask_u16_sse)
BTF_ID_FLAGS(func, bpf_find_mask_u32_avx)
BTF_ID_FLAGS(func, bpf_find_mask_u16_avx)
BTF_ID_FLAGS(func, bpf_find_mask_u16_sse)
BTF_ID_FLAGS(func, bpf_tzcnt_u32)
BTF_ID_FLAGS(func, bpf_tzcnt_u16)
BTF_ID_FLAGS(func, bpf_find_min_u16_sse)
BTF_SET8_END(bpf_cmp_alg_simd_kfunc_ids)

static const struct btf_kfunc_id_set bpf_cmp_alg_simd_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_cmp_alg_simd_kfunc_ids,
};

static int __init bpf_cmp_alg_simd_init(void)
{
	int ret;

	if ((ret = register_btf_kfunc_id_set(
		     BPF_PROG_TYPE_XDP, &bpf_cmp_alg_simd_kfunc_set)) < 0) {
		pr_err("bpf_cmp_alg_simd: failed to register kfunc set: %d\n",
		       ret);
		return ret;
	}

	pr_info("bpf_cmp_alg_simd: initialized\n");
	return 0;
}

static void __exit bpf_cmp_alg_simd_exit(void)
{
	pr_info("bpf_cmp_alg_simd: exiting\n");
}

/* Register module functions */
module_init(bpf_cmp_alg_simd_init);
module_exit(bpf_cmp_alg_simd_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yang Hanlin");
MODULE_DESCRIPTION("");
MODULE_VERSION("0.0.1");
