#pragma once 

#include "common.h"
#include "linux/printk.h"
#include "xxhash_simd.h"

static const u32 seeds[] = {
	0xec5853, 0xec5859, 0xec5861, 0xec587f, 0xec58a7, 0xec58b3, 0xec58c7,
	0xec58d1, 0xec5853, 0xec5859, 0xec5861, 0xec587f, 0xec58a7, 0xec58b3,
	0xec58c7, 0xec58d1, 0xec5853, 0xec5859, 0xec5861, 0xec587f, 0xec58a7,
	0xec58b3, 0xec58c7, 0xec58d1, 0xec5853, 0xec5859, 0xec5861, 0xec587f,
	0xec58a7, 0xec58b3, 0xec58c7, 0xec58d1, 0xec5853, 0xec5859, 0xec5861,
	0xec587f, 0xec58a7, 0xec58b3, 0xec58c7, 0xec58d1, 0xec5853, 0xec5859,
	0xec5861, 0xec587f, 0xec58a7, 0xec58b3, 0xec58c7, 0xec58d1, 0xec5853,
	0xec5859, 0xec5861, 0xec587f, 0xec58a7, 0xec58b3, 0xec58c7, 0xec58d1,
	0xec5853, 0xec5859, 0xec5861, 0xec587f, 0xec58a7, 0xec58b3, 0xec58c7,
	0xec58d1,
};

static __m256i SEEDS_VEC;

#define NO_TEAR_ADD(x, val) WRITE_ONCE((x), READ_ONCE(x) + (val))

static inline __attribute__((always_inline)) void hash_post_init(void)
{
        SEEDS_VEC = _mm256_loadu_si256((const __m256i_u *)seeds);
}

static inline __attribute__((always_inline)) void
hash_smid_cnt_u32(const struct pkt_5tuple *buf, u32 *values, u64 size,
		  u32 column_shift)
{
        column_shift = column_shift & 0x1F;
        u32 colunms = (1 << column_shift);
	u32 hash_num = (size >> column_shift >> 2);
	if (hash_num > 8) {
		pr_err("hash num > 8");
		return;
	}

	const __m256i hashes_vec = xxh32_avx2_pkt5(buf, &SEEDS_VEC);
	const u32 *hashes = (const u32 *)&hashes_vec;

	for (u32 i = 0; i < hash_num; i++) {
		u32 target_idx = hashes[i] & (colunms - 1);
		NO_TEAR_ADD(*(values + i * colunms + target_idx), 1);
	}
}
