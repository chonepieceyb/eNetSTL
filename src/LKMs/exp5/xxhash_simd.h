/* xxHash SIMD implementation; all functions are inline */

#ifndef _XXHASH_SIMD_H
#define _XXHASH_SIMD_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <asm/unaligned.h>

// This macro is required to include <immtrin.h> in the kernel
#ifdef __clang__
#define __MM_MALLOC_H
#else /* __clang__ */
#define _MM_MALLOC_H_INCLUDED
#endif /* __clang__ */

#else /* __KERNEL__ */
#include <stdint.h>
#include <stdio.h>

#define get_unaligned_le32(p) (*(const u32 *)(p))

typedef uint32_t u32;
typedef uint64_t u64;
typedef uint8_t u8;
#endif /* __KERNEL__ */

#include <immintrin.h>

struct pkt_5tuple;

/**
 * xxh32_avx2_pkt5 - 32-bit AVX2 implementation of fasthash; calculates 8
 * hashes for 8 seeds in parallel
 * 
 * @buf: data buffer (size must be 13)
 * @seeds: the seeds vector (containing 4 64-bit integers)
 */
static inline __attribute__((always_inline)) __m256i
xxh32_avx2_pkt5(const struct pkt_5tuple *buf, const __m256i *seeds_vec);

/**
 * xxh32_avx2_pkt5_pkts: 32-bit AVX2 implementation of fasthash; calculates 8
 * hashes for 8 data buffers in parallel
 * 
 * @b0: vector containing 8 32-bit integers, each representing bytes 0-3 of
 *      data being hashed
 * @b1: vector containing 8 32-bit integers, each representing bytes 4-7 of
 *      data being hashed
 * @b2: vector containing 8 32-bit integers, each representing bytes 8-11 of
 *      data being hashed
 * @b3: vector containing 8 32-bit integers, each representing bytes 12-15 of
 *      data being hashed
 * @seed: the seed
 */
static inline __attribute__((always_inline)) __m256i
xxh32_avx2_pkt5_pkts(const __m256i *b0, const __m256i *b1, const __m256i *b2,
		     const __m256i *b3, const u32 seed);

/**
 * xxh_init: initializes constants used in xxhash; must be called at least
 * once before calls to any other xxhash functions
 */
static inline __attribute__((always_inline)) void xxh_init(void);

static const size_t PKT5_LENGTH = 13;
static const size_t PKT5_PKTS_LENGTH = 16;
static const u32 PRIME32_1 = 2654435761U;
static const u32 PRIME32_2 = 2246822519U;
static const u32 PRIME32_3 = 3266489917U;
static const u32 PRIME32_4 = 668265263U;
static const u32 PRIME32_5 = 374761393U;

static __m256i PKT5_LENGTH_VEC, PKT5_PKTS_LENGTH_VEC, PRIME32_1_VEC,
	PRIME32_2_VEC, PRIME32_3_VEC, PRIME32_4_VEC, PRIME32_5_VEC,
	PRIME32_5_PLUS_PKT5_LENGTH_VEC;

#define xxh_rotl32_avx2(x, r)                        \
	_mm256_or_si256(_mm256_slli_epi32((x), (r)), \
			_mm256_srli_epi32((x), 32 - (r)))

#define xxh32_round_avx2(vv, input)                                        \
	({                                                                 \
		__m256i tmp = _mm256_add_epi32(                            \
			(vv), _mm256_mullo_epi32((input), PRIME32_2_VEC)); \
		tmp = xxh_rotl32_avx2(tmp, 13);                            \
		tmp = _mm256_mullo_epi32(tmp, PRIME32_1_VEC);              \
	})

static inline __attribute__((always_inline)) __m256i
xxh32_avx2_pkt5(const struct pkt_5tuple *buf, const __m256i *seeds_vec)
{
	const u8 *p = (const u8 *)buf;
	const u8 *b_end = p + PKT5_LENGTH;
	__m256i hh32 =
		_mm256_add_epi32(*seeds_vec, PRIME32_5_PLUS_PKT5_LENGTH_VEC);

#pragma GCC unroll 3
	for (; p + 4 <= b_end; p += 4) {
		hh32 = _mm256_add_epi32(
			hh32,
			_mm256_set1_epi32(get_unaligned_le32(p) * PRIME32_3));
		hh32 = _mm256_mullo_epi32(xxh_rotl32_avx2(hh32, 17),
					  PRIME32_4_VEC);
	}

	hh32 = _mm256_add_epi32(hh32, _mm256_set1_epi32((*p) * PRIME32_5));
	hh32 = _mm256_mullo_epi32(xxh_rotl32_avx2(hh32, 11), PRIME32_1_VEC);

	hh32 = _mm256_xor_si256(hh32, _mm256_srli_epi32(hh32, 15));
	hh32 = _mm256_mullo_epi32(hh32, PRIME32_2_VEC);
	hh32 = _mm256_xor_si256(hh32, _mm256_srli_epi32(hh32, 13));
	hh32 = _mm256_mullo_epi32(hh32, PRIME32_3_VEC);
	hh32 = _mm256_xor_si256(hh32, _mm256_srli_epi32(hh32, 16));

	return hh32;
}

static inline __attribute__((always_inline)) __m256i
xxh32_avx2_pkt5_pkts(const __m256i *b0, const __m256i *b1, const __m256i *b2,
		     const __m256i *b3, const u32 seed)
{
	__m256i hh32 = PKT5_PKTS_LENGTH_VEC;

	__m256i vv1 = _mm256_set1_epi32(seed + PRIME32_1 + PRIME32_2);
	__m256i vv2 = _mm256_set1_epi32(seed + PRIME32_2);
	__m256i vv3 = _mm256_set1_epi32(seed);
	__m256i vv4 = _mm256_set1_epi32(seed - PRIME32_1);

	vv1 = xxh32_round_avx2(vv1, *b0);
	vv2 = xxh32_round_avx2(vv2, *b1);
	vv3 = xxh32_round_avx2(vv3, *b2);
	vv4 = xxh32_round_avx2(vv4, *b3);

	hh32 = xxh_rotl32_avx2(vv1, 1);
	hh32 = _mm256_add_epi32(hh32, xxh_rotl32_avx2(vv2, 7));
	hh32 = _mm256_add_epi32(hh32, xxh_rotl32_avx2(vv3, 12));
	hh32 = _mm256_add_epi32(hh32, xxh_rotl32_avx2(vv4, 18));

	hh32 = _mm256_xor_si256(hh32, _mm256_srli_epi32(hh32, 15));
	hh32 = _mm256_mullo_epi32(hh32, PRIME32_2_VEC);
	hh32 = _mm256_xor_si256(hh32, _mm256_srli_epi32(hh32, 13));
	hh32 = _mm256_mullo_epi32(hh32, PRIME32_3_VEC);
	hh32 = _mm256_xor_si256(hh32, _mm256_srli_epi32(hh32, 16));

	return hh32;
}

static inline __attribute__((always_inline)) void xxh_init(void)
{
	PRIME32_1_VEC = _mm256_set1_epi32(PRIME32_1);
	PRIME32_2_VEC = _mm256_set1_epi32(PRIME32_2);
	PRIME32_3_VEC = _mm256_set1_epi32(PRIME32_3);
	PRIME32_4_VEC = _mm256_set1_epi32(PRIME32_4);
	PRIME32_5_VEC = _mm256_set1_epi32(PRIME32_5);
	PKT5_LENGTH_VEC = _mm256_set1_epi32(PKT5_LENGTH);
	PKT5_PKTS_LENGTH_VEC = _mm256_set1_epi32(PKT5_PKTS_LENGTH);
	PRIME32_5_PLUS_PKT5_LENGTH_VEC =
		_mm256_set1_epi32(PRIME32_5 + PKT5_LENGTH);
}

#endif
