#ifndef _FASTHASH_SIMD_H
#define _FASTHASH_SIMD_H

#ifdef __KERNEL__
#include <linux/types.h>

// This macro is required to include <immtrin.h> in the kernel
#define _MM_MALLOC_H_INCLUDED
#else
#include <stdint.h>
#include <stdio.h>

typedef uint32_t u32;
typedef uint64_t u64;
#endif

#include <immintrin.h>

struct pkt_5tuple;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * fasthash32_avx2 - 32-bit AVX2 implementation of fasthash; calculates 4
 * hashes for 4 seeds in parallel
 *
 * @buf: data buffer
 * @len: data size
 * @seeds: the seeds (size must be at least 4)
 * @dest: destination to store the hashes (size must be at least 4)
 */
#ifdef FASTHASH_INLINE
static inline
	__attribute__((always_inline))
#endif
	void
	fasthash32_avx2(const void *buf, size_t len, const u32 *seeds,
			u32 *dest);

/**
 * fasthash32_alt_avx2 - alternative 32-bit AVX2 implementation of fasthash;
 * calculates 8 hashes for 8 seeds in parallel
 *
 * @buf: data buffer
 * @len: data size
 * @seeds: the seeds (size must be at least 8)
 * @dest: destination to store the hashes (size must be at least 8)
 */
#ifdef FASTHASH_INLINE
static inline
	__attribute__((always_inline))
#endif
	void
	fasthash32_alt_avx2(const void *buf, size_t len, const u32 *seeds,
			    u32 *dest);

/**
 * fasthash32_alt_avx2_pkt5 - alternative 32-bit AVX2 implementation of
 * fasthash; calculates 8 hashes for 8 seeds in parallel
 * 
 * @buf: data buffer (size must be 13)
 * @seeds: the seeds (size must be at least 8)
 * @dest: destination to store the hashes (size must be at least 8)
 */
#ifdef FASTHASH_INLINE
static inline
	__attribute__((always_inline))
#endif
	void
	fasthash32_alt_avx2_pkt5(const struct pkt_5tuple *buf, const u32 *seeds,
				 u32 *dest);

/**
 * fasthash64_avx2 - 64-bit AVX2 implementation of fasthash; calculates 4
 * hashes for 4 seeds in parallel
 *
 * @buf: data buffer
 * @len: data size
 * @seeds: the seeds (size must be at least 4)
 * @dest: destination to store the hashes (size must be at least 4)
 */
#ifdef FASTHASH_INLINE
static inline
	__attribute__((always_inline))
#endif
	void
	fasthash64_avx2(const struct pkt_5tuple *buf, size_t len,
			const u64 *seeds, u64 *dest);

/**
 * _fasthash64_avx2 - 64-bit AVX2 implementation of fasthash; calculates 4
 * hashes for 4 seeds in parallel
 * 
 * @buf: data buffer
 * @len: data size
 * @seeds_vec: the seeds vector (containing 4 64-bit integers)
 */
#ifdef FASTHASH_INLINE
static inline __attribute__((always_inline))
#endif
__m256i
_fasthash64_avx2(const void *buf, size_t len, const __m256i *seeds_vec);

/**
 * _fasthash64_avx2_pkt5 - 64-bit AVX2 implementation of fasthash; calculates 4
 * hashes for 4 seeds in parallel
 * 
 * @buf: data buffer (size must be 13)
 * @seeds_vec: the seeds vector (containing 4 64-bit integers)
 */
#ifdef FASTHASH_INLINE
static inline __attribute__((always_inline))
#endif
__m256i
_fasthash64_avx2_pkt5(const struct pkt_5tuple *buf, const __m256i *seeds_vec);

/**
 * _fasthash64_avx2_pkt5_pkts - 64-bit AVX2 implementation of fasthash;
 * calculates 4 hashes for 4 data buffers in parallel
 * 
 * @lo: vector containing 4 64-bit integers, each representing the lower 8
 *      bytes of data being hashed
 * @hi: vector containing 4 64-bit integers, each representing the higher 8
 *      bytes of data being hashed
 * @seed: the seed
 */
#ifdef FASTHASH_INLINE
static inline __attribute__((always_inline))
#endif
__m256i
_fasthash64_avx2_pkt5_pkts(const __m256i *lo, const __m256i *hi,
			   const u64 seed);

/**
 * fasthash_init: initializes constants used in fasthash; must be called at
 * least once before calls to any other fasthash functions
 */
#ifdef FASTHASH_INLINE
static inline
	__attribute__((always_inline))
#endif
	void
	fasthash_init(void);

#ifdef __cplusplus
}
#endif

#ifdef FASTHASH_INLINE
#include "fasthash_simd.c"
#endif

#endif
