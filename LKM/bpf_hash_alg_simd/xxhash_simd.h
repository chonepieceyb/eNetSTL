#ifndef _XXHASH_SIMD_H
#define _XXHASH_SIMD_H

#ifdef __KERNEL__
#include <linux/types.h>

// This macro is required to include <immtrin.h> in the kernel
#define _MM_MALLOC_H_INCLUDED
#else
#include <stdint.h>
#include <stdio.h>

typedef uint32_t u32;
typedef uint64_t u64;
typedef uint8_t u8;
#endif

#include <immintrin.h>

struct pkt_5tuple;

/**
 * xxh32_avx2_pkt5 - 32-bit AVX2 implementation of fasthash; calculates 8
 * hashes for 8 seeds in parallel
 * 
 * @buf: data buffer (size must be 13)
 * @seeds: the seeds vector (containing 4 64-bit integers)
 */
#ifdef XXHASH_INLINE
static inline __attribute__((always_inline))
#endif
__m256i
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
#ifdef XXHASH_INLINE
static inline __attribute__((always_inline))
#endif
__m256i
xxh32_avx2_pkt5_pkts(const __m256i *b0, const __m256i *b1, const __m256i *b2,
		     const __m256i *b3, const u32 seed);

/**
 * xxh_init: initializes constants used in xxhash; must be called at least
 * once before calls to any other xxhash functions
 */
#ifdef XXHASH_INLINE
static inline
	__attribute__((always_inline))
#endif
	void
	xxh_init(void);

#ifdef XXHASH_INLINE
#include "xxhash_simd.c"
#endif

#endif
