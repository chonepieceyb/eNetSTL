#pragma once

#include "common.h"
#include <asm-generic/int-ll64.h>

#define _mm256_loadu_si256_optional(ptr)                                       \
	(u64)(ptr) & ((1 << 5) - 1) ? _mm256_loadu_si256((__m256i_u *)(ptr)) : \
				      (*(__m256i *)(ptr))

#define _mm_loadu_si128_optional(ptr)                                       \
	(u64)(ptr) & ((1 << 5) - 1) ? _mm_loadu_si128((__m128i_u *)(ptr)) : \
				      *(__m128i *)(ptr)


static inline u32 __find_mask_u16_avx(const u16 *arr, u16 val)
{
	__m256i arr_vec = _mm256_loadu_si256_optional((const __m256i_u *)arr),
		val_vec = _mm256_set1_epi16(val);
	__m256i cmp = _mm256_cmpeq_epi16(arr_vec, val_vec);
	u32 mask = _mm256_movemask_epi8(cmp);
	return mask;
}

static inline int __k16_cmp_eq(const void *key1, size_t key1_sz,
			       const void *key2, size_t key2_sz)
{
    if (!(key1_sz == key2_sz && key1_sz >= 128))
        return 0;
	const __m128i k1 = _mm_loadu_si128((const __m128i *)key1);
	const __m128i k2 = _mm_loadu_si128((const __m128i *)key2);
	const __m128i x = _mm_xor_si128(k1, k2);
	int ret = !_mm_test_all_zeros(x, x);
	return ret;
}

static inline u32 __find_u16_avx(const u16 *arr, u16 val)
{
	u32 mask = __find_mask_u16_avx(arr, val);
	return __tzcnt_u32(mask) >> 1;
}
