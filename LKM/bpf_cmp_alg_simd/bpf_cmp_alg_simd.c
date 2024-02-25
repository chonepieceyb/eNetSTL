#include <asm-generic/int-ll64.h>
#include <linux/bitops.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>
#include <linux/printk.h>

#include "../crc32hash.h"

// This macro is required to include <immintrin.h> in the kernel
#define _MM_MALLOC_H_INCLUDED
#include <immintrin.h>

#include "crc.h"

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

__bpf_kfunc u32 bpf_crc32_hash(const void *key, u32 key__sz, u32 seed)
{
	return rte_hash_crc(key, key__sz, seed);
}
EXPORT_SYMBOL_GPL(bpf_crc32_hash);

__bpf_kfunc uint32_t bpf_htss_sig_cmp(const void *sigs, size_t sigs__sz,
				      __u16 tmp_sig)
{
	__u32 hitmask = _mm256_movemask_epi8((__m256i)_mm256_cmpeq_epi16(
		_mm256_load_si256((__m256i const *)sigs),
		_mm256_set1_epi16(tmp_sig)));
	return hitmask;
}
EXPORT_SYMBOL_GPL(bpf_htss_sig_cmp);

__bpf_kfunc uint32_t bpf_htss_bucket_search(__u16 *sigs, size_t sigs__sz,
					    __u16 tmp_sig, __u16 *sets,
					    size_t sets__sz)
{
	__u32 hitmask = _mm256_movemask_epi8((__m256i)_mm256_cmpeq_epi16(
		_mm256_load_si256((__m256i const *)sigs),
		_mm256_set1_epi16(tmp_sig)));
	while (hitmask) {
		__u32 hit_idx = __builtin_ctz(hitmask) >> 1;
		if (sets[hit_idx] != 0) {
			return sets[hit_idx];
		}
		hitmask &= ~(3U << ((hit_idx) << 1));
	}
	return 0;
}
EXPORT_SYMBOL_GPL(bpf_htss_bucket_search);

__bpf_kfunc uint32_t bpf_crc32c_sse(const void *data, uint32_t data__sz,
				    uint32_t init_val)
{
	return crc32c(data, data__sz, init_val);
}
EXPORT_SYMBOL_GPL(bpf_crc32c_sse);

__bpf_kfunc u32 bpf__find_min_u16_sse(const u16 *arr, size_t len, u16 *min_val)
{
	u16 value, min_value = arr[0];
	u32 i, min_index = 0;
	__m128i arr_vec, res;

	for (i = 0; i < len; i += 8) {
		arr_vec = _mm_loadu_si128((__m128i_u *)(arr + i));
		res = _mm_minpos_epu16(arr_vec);
		value = _mm_extract_epi16(res, 0);
		if (value < min_value) {
			min_value = value;
			min_index = i + _mm_extract_epi16(res, 1);
		}
	}

	*min_val = min_value;
	return min_index;
}
EXPORT_SYMBOL_GPL(bpf__find_min_u16_sse);

__bpf_kfunc int bpf_k16_cmp_eq(const void *key1, size_t key1__sz,
			       const void *key2, size_t key2__sz)
{
	const __m128i k1 = _mm_loadu_si128((const __m128i *)key1);
	const __m128i k2 = _mm_loadu_si128((const __m128i *)key2);
	const __m128i x = _mm_xor_si128(k1, k2);
	int ret = !_mm_test_all_zeros(x, x);

	return ret;
}
EXPORT_SYMBOL_GPL(bpf_k16_cmp_eq);

__bpf_kfunc int bpf_k32_cmp_eq(const void *key1, size_t key1__sz,
			       const void *key2, size_t key2__sz)
{
	const __m256i k1 = _mm256_loadu_si256((const __m256i *)key1);
	const __m256i k2 = _mm256_loadu_si256((const __m256i *)key2);
	const __m256i x = _mm256_xor_si256(k1, k2);
	int ret = !_mm256_testz_si256(x, x);

	return ret;
}
EXPORT_SYMBOL_GPL(bpf_k32_cmp_eq);

__bpf_kfunc void bpf_mm256_cmpeq_epi32(const u32 *arr, u32 val, u32 *dest)
{
	__m256i arr_vec = _mm256_loadu_si256_optional(arr),
		val_vec = _mm256_set1_epi32(val);
	__m256i cmp = _mm256_cmpeq_epi32(arr_vec, val_vec);
	_mm256_storeu_si256((__m256i_u *)dest, cmp);
}
EXPORT_SYMBOL_GPL(bpf_mm256_cmpeq_epi32);

__bpf_kfunc void bpf_mm256_cmpeq_epi16(const u16 *arr, u16 val, u16 *dest)
{
	__m256i arr_vec = _mm256_loadu_si256_optional((const __m256i_u *)arr),
		val_vec = _mm256_set1_epi16(val);
	__m256i cmp = _mm256_cmpeq_epi16(arr_vec, val_vec);
	_mm256_storeu_si256((__m256i_u *)dest, cmp);
}
EXPORT_SYMBOL_GPL(bpf_mm256_cmpeq_epi16);

__bpf_kfunc u32 bpf_mm256_movemask_epi8(const u8 *arr)
{
	__m256i arr_vec = _mm256_loadu_si256_optional((const __m256i_u *)arr);
	return _mm256_movemask_epi8(arr_vec);
}
EXPORT_SYMBOL_GPL(bpf_mm256_movemask_epi8);

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
BTF_ID_FLAGS(func, bpf_crc32_hash)
BTF_ID_FLAGS(func, bpf_htss_sig_cmp)
BTF_ID_FLAGS(func, bpf_htss_bucket_search)
BTF_ID_FLAGS(func, bpf_crc32c_sse)
BTF_ID_FLAGS(func, bpf__find_min_u16_sse)
BTF_ID_FLAGS(func, bpf_k16_cmp_eq)
BTF_ID_FLAGS(func, bpf_k32_cmp_eq)
BTF_ID_FLAGS(func, bpf_mm256_cmpeq_epi32)
BTF_ID_FLAGS(func, bpf_mm256_cmpeq_epi16)
BTF_ID_FLAGS(func, bpf_mm256_movemask_epi8)
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
