#ifndef FASTHASH_INLINE
#include "fasthash_simd.h"
#endif

static const u64 m = 0x880355f21e6d1965ULL;
static __m256i mm;
static __m256i mm_times_13;
static __m256i mix_constant;
static __m256i cvt_mask;
static __m256i mullo_mask;

#if defined(__AVX512DQ__) && defined(__AVX512VL__)
#define _mm256_mullo_epi64_emulated _mm256_mullo_epi64
#else
#define _mm256_mullo_epi64_emulated(a, b)                                     \
	({                                                                    \
		__m256i lo = _mm256_mul_epu32((a), (b));                      \
		__m256i hi = _mm256_and_si256(                                \
			_mm256_add_epi32(                                     \
				_mm256_mullo_epi32(_mm256_slli_si256((a), 4), \
						   (b)),                      \
				_mm256_mullo_epi32(                           \
					(a), _mm256_slli_si256((b), 4))),     \
			mullo_mask);                                          \
		_mm256_add_epi32(lo, hi);                                     \
	})
#endif

#if defined(__AVX512F__) && defined(__AVX512VL__)
#define _mm256_cvtepi64_epi32_emulated _mm256_cvtepi64_epi32
#else
#define _mm256_cvtepi64_epi32_emulated(a)                                 \
	({                                                                \
		__m256i tmp = _mm256_permutevar8x32_epi32((a), cvt_mask); \
		_mm256_extracti128_si256(tmp, 0);                         \
	})
#endif

#define fasthash_mix_avx2(hh)                                               \
	({                                                                  \
		(hh) = _mm256_xor_si256((hh), _mm256_srli_epi64((hh), 23)); \
		(hh) = _mm256_mullo_epi64_emulated((hh), mix_constant);     \
		(hh) = _mm256_xor_si256((hh), _mm256_srli_epi64((hh), 47)); \
	})

#ifdef FASTHASH_INLINE
static inline __attribute__((always_inline))
#endif
__m256i
_fasthash64_avx2(const void *buf, size_t len, const __m256i *seeds_vec)
{
	const u64 *pos = (const u64 *)buf;
	const u64 *end = pos + (len / 8);
	const unsigned char *pos2;
	u64 v;

	__m256i hh = _mm256_xor_si256(*seeds_vec, _mm256_set1_epi64x(len * m));
	__m256i vv;

	while (pos != end) {
		v = *pos++;
		vv = _mm256_set1_epi64x(v);
		hh = _mm256_xor_si256(hh, fasthash_mix_avx2(vv));
		hh = _mm256_mullo_epi64_emulated(hh, mm);
	}

	pos2 = (const unsigned char *)pos;
	vv = _mm256_set1_epi64x(0);

	switch (len & 7) {
	case 7:
		vv = _mm256_xor_si256(vv,
				      _mm256_set1_epi64x((u64)pos2[6] << 48));
	case 6:
		vv = _mm256_xor_si256(vv,
				      _mm256_set1_epi64x((u64)pos2[5] << 40));
	case 5:
		vv = _mm256_xor_si256(vv,
				      _mm256_set1_epi64x((u64)pos2[4] << 32));
	case 4:
		vv = _mm256_xor_si256(vv,
				      _mm256_set1_epi64x((u64)pos2[3] << 24));
	case 3:
		vv = _mm256_xor_si256(vv,
				      _mm256_set1_epi64x((u64)pos2[2] << 16));
	case 2:
		vv = _mm256_xor_si256(vv,
				      _mm256_set1_epi64x((u64)pos2[1] << 8));
	case 1:
		vv = _mm256_xor_si256(vv, _mm256_set1_epi64x((u64)pos2[0]));
		hh = _mm256_xor_si256(hh, fasthash_mix_avx2(vv));
		hh = _mm256_mullo_epi64_emulated(hh, mm);
	}

	hh = fasthash_mix_avx2(hh);

	return hh;
}

#ifdef FASTHASH_INLINE
static inline __attribute__((always_inline))
#endif
__m256i
_fasthash64_avx2_pkt5(const struct pkt_5tuple *buf, const __m256i *seeds_vec)
{
	const u64 *pos = (const u64 *)buf;
	const unsigned char *pos2;

	__m256i hh = _mm256_xor_si256(*seeds_vec, mm_times_13);

	__m256i vv;

	vv = _mm256_set1_epi64x(*pos++);
	hh = _mm256_xor_si256(hh, fasthash_mix_avx2(vv));
	hh = _mm256_mullo_epi64_emulated(hh, mm);

	pos2 = (const unsigned char *)pos;
	vv = _mm256_set1_epi64x(0);

	vv = _mm256_xor_si256(vv, _mm256_set1_epi64x((u64)pos2[4] << 32));
	vv = _mm256_xor_si256(vv, _mm256_set1_epi64x((u64)pos2[3] << 24));
	vv = _mm256_xor_si256(vv, _mm256_set1_epi64x((u64)pos2[2] << 16));
	vv = _mm256_xor_si256(vv, _mm256_set1_epi64x((u64)pos2[1] << 8));
	vv = _mm256_xor_si256(vv, _mm256_set1_epi64x((u64)pos2[0]));
	hh = _mm256_xor_si256(hh, fasthash_mix_avx2(vv));
	hh = _mm256_mullo_epi64_emulated(hh, mm);

	hh = fasthash_mix_avx2(hh);

	return hh;
}

#ifdef FASTHASH_INLINE
static inline __attribute__((always_inline))
#endif
__m256i
_fasthash64_avx2_pkt5_pkts(const __m256i *lo, const __m256i *hi, const u64 seed)
{
	const __m256i seeds = _mm256_set1_epi64x(seed);
	__m256i hh = _mm256_xor_si256(seeds, _mm256_set1_epi64x(16 * m));

	__m256i vv = *lo;
	hh = _mm256_xor_si256(hh, fasthash_mix_avx2(vv));
	hh = _mm256_mullo_epi64_emulated(hh, mm);

	vv = *hi;
	hh = _mm256_xor_si256(hh, fasthash_mix_avx2(vv));
	hh = _mm256_mullo_epi64_emulated(hh, mm);

	hh = fasthash_mix_avx2(hh);

	return hh;
}

#ifdef FASTHASH_INLINE
static inline
	__attribute__((always_inline))
#endif
	void
	fasthash64_avx2(const struct pkt_5tuple *buf, size_t len,
			const u64 *seeds, u64 *dest)
{
	__m256i seeds_vec = _mm256_loadu_si256((const __m256i_u *)seeds);

	const __m256i hh = _fasthash64_avx2(buf, len, &seeds_vec);

	_mm256_storeu_si256((__m256i_u *)dest, hh);
}

#ifdef FASTHASH_INLINE
static inline
	__attribute__((always_inline))
#endif
	void
	fasthash32_avx2(const void *buf, size_t len, const u32 *seeds,
			u32 *dest)
{
	__m128i seeds_vec = _mm_loadu_si128((const __m128i_u *)seeds);
	__m256i seeds_vec64 = _mm256_cvtepi32_epi64(seeds_vec);

	__m256i hh64 = _fasthash64_avx2(buf, len, &seeds_vec64);
	hh64 = _mm256_sub_epi64(hh64, _mm256_srli_epi64(hh64, 32));
	__m128i hh = _mm256_cvtepi64_epi32_emulated(hh64);

	_mm_storeu_si128((__m128i_u *)dest, hh);
}

#ifdef FASTHASH_INLINE
static inline
	__attribute__((always_inline))
#endif
	void
	fasthash32_alt_avx2(const void *buf, size_t len, const u32 *seeds,
			    u32 *dest)
{
	__m256i seeds_vec = _mm256_loadu_si256((const __m256i_u *)seeds);

	const __m256i hh = _fasthash64_avx2(buf, len, &seeds_vec);

	_mm256_storeu_si256((__m256i_u *)dest, hh);
}

#ifdef FASTHASH_INLINE
static inline
	__attribute__((always_inline))
#endif
	void
	fasthash32_alt_avx2_pkt5(const struct pkt_5tuple *buf, const u32 *seeds,
				 u32 *dest)
{
	__m256i seeds_vec = _mm256_loadu_si256((const __m256i_u *)seeds);

	const __m256i hh = _fasthash64_avx2_pkt5(buf, &seeds_vec);

	_mm256_storeu_si256((__m256i_u *)dest, hh);
}

#ifdef FASTHASH_INLINE
static inline
	__attribute__((always_inline))
#endif
	void
	fasthash_init(void)
{
	mm = _mm256_set1_epi64x(m);
	mm_times_13 = _mm256_set1_epi64x(13 * m);
	mix_constant = _mm256_set1_epi64x(0x2127599bf4325c37ULL);
	cvt_mask = _mm256_set_epi32(7, 5, 3, 1, 6, 4, 2, 0);
	mullo_mask = _mm256_set_epi32(0xffffffff, 0, 0xffffffff, 0, 0xffffffff,
				      0, 0xffffffff, 0);
}
