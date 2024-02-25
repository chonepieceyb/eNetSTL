#include "common.h"
#include "vmlinux.h"
#include "bpf_hash_alg_simd.h"
#include "crc.h"

#define PACKET_ATTRS                                                    \
	.src_ip = 0x01020304, .dst_ip = 0x05060708, .src_port = 0x090a, \
	.dst_port = 0x0b0c, .proto = 0x06
#define SEEDx1 0x01020304
#define SEEDx4 SEEDx1, 0x05060708, 0x090a0b0c, 0x0d0e0f10
#define SEEDx8 SEEDx4, 0x11121314, 0x15161718, 0x191a1b1c, 0x1d1e1f20
#define M 0x880355f21e6d1965ULL

char _license[] SEC("license") = "GPL";

static inline void __memcpy_n(u8 *dest, const u8 *src, size_t n)
{
	for (int i = 0; i < n; i++) {
		dest[i] = src[i];
	}
}

static inline void test_bpf_xxh32_avx2_pkt5(void)
{
	struct pkt_5tuple pkt = { PACKET_ATTRS };
	u32 seeds[8] = { SEEDx8 };
	u32 dest[8] = { 0 };

	log_info("xxh32_avx2_pkt5() test started\n");

	bpf_xxh32_avx2_pkt5(&pkt, seeds, dest);

	for (int i = 0; i < 8; i++) {
		log_debug("dest[%d] = 0x%x\n", i, dest[i]);
	}

	log_info("xxh32_avx2_pkt5() test passed\n");
}

static inline void test_bpf_xxh32_avx2_pkt5_pkts(void)
{
	struct pkt_5tuple pkt = { PACKET_ATTRS };
	u32 seed = SEEDx1;
	u32 dest[8] = { 0 };

	log_info("xxh32_avx2_pkt5_pkts() test started\n");

	u32 data[32] = { 0 };
	int i, j;
	size_t copy_size;
	for (i = 0; i < 4; i++) {
		copy_size = i != 3 ? sizeof(u32) : 1;
		for (j = 0; j < 8; j++) {
			__memcpy_n((u8 *)(data + i * 8 + j), (u8 *)&seed,
				   copy_size);
		}
	}

	bpf_xxh32_avx2_pkt5_pkts(data, seed, dest);

	for (int i = 0; i < 8; i++) {
		/* 8 hashes should be the same */
		log_debug("dest[%d] = 0x%x\n", i, dest[i]);
	}

	log_info("xxh32_avx2_pkt5_pkts() test passed\n");
}

static inline void test_bpf_fasthash32_avx2(void)
{
	struct pkt_5tuple pkt = { PACKET_ATTRS };
	u32 seeds[4] = { SEEDx4 };
	u32 dest[4] = { 0 };

	log_info("bpf_fasthash32_avx2() test started\n");

	bpf_fasthash32_avx2(&pkt, sizeof(pkt), seeds, dest);

	for (int i = 0; i < 4; i++) {
		log_debug("dest[%d] = 0x%x\n", i, dest[i]);
	}

	log_info("bpf_fasthash32_avx2() test passed\n");
}

static inline void test_bpf_fasthash32_alt_avx2(void)
{
	struct pkt_5tuple pkt = { PACKET_ATTRS };
	u32 seeds[8] = { SEEDx8 };
	u32 dest[8] = { 0 };

	log_info("bpf_fasthash32_alt_avx2() test started\n");

	bpf_fasthash32_alt_avx2(&pkt, sizeof(pkt), seeds, dest);

	for (int i = 0; i < 8; i++) {
		log_debug("dest[%d] = 0x%x\n", i, dest[i]);
	}

	log_info("bpf_fasthash32_alt_avx2() test passed\n");
}

static inline void test_bpf_fasthash32_alt_avx2_pkt5(void)
{
	struct pkt_5tuple pkt = { PACKET_ATTRS };
	u32 seeds[8] = { SEEDx8 };
	u32 dest[8] = { 0 };

	log_info("bpf_fasthash32_alt_avx2_pkt5() test started\n");

	bpf_fasthash32_alt_avx2_pkt5(&pkt, seeds, dest);

	for (int i = 0; i < 8; i++) {
		log_debug("dest[%d] = 0x%x\n", i, dest[i]);
	}

	log_info("bpf_fasthash32_alt_avx2_pkt5() test passed\n");
}

struct mem_block {
	u8 data[32];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 64);
	__type(key, u32);
	__type(value, struct mem_block);
} mem_blocks SEC(".maps");

static inline void *alloc_mem_block(u32 *i)
{
	struct mem_block *block;

	block = bpf_map_lookup_elem(&mem_blocks, i);
	if (!block) {
		log_debug("failed to allocate memory\n");
		return NULL;
	}

	*i = *i + 1;
	return block;
}

static inline void bpf_mm256_mullo_epi64_emulated(s64 *dest, const s64 *a,
						  const s64 *b, u32 *i,
						  const u8 *mullo_mask)
{
	u8 *lo = (u8 *)(dest), *hi = alloc_mem_block(i),
	   *tmp1 = alloc_mem_block(i), *tmp2 = alloc_mem_block(i);
	if (!hi || !tmp1 || !tmp2) {
		return;
	}

	bpf_mm256_mul_epu32((u32 *)lo, (const u32 *)(a), (const u32 *)(b));
	bpf_mm256_slli_si256_4(tmp1, (const u8 *)(a));
	bpf_mm256_mullo_epi32((s32 *)tmp1, (const s32 *)tmp1, (const s32 *)(b));
	bpf_mm256_slli_si256_4(tmp2, (const u8 *)(b));
	bpf_mm256_mullo_epi32((s32 *)tmp2, (const s32 *)tmp2, (const s32 *)(a));
	bpf_mm256_add_epi32((s32 *)hi, (const s32 *)tmp1, (const s32 *)tmp2);
	bpf_mm256_and_si256((u8 *)hi, (const u8 *)hi, (const u8 *)mullo_mask);
	bpf_mm256_add_epi32((s32 *)lo, (const s32 *)lo, (const s32 *)hi);
}

static inline void bpf_fasthash_mix_avx2(u8 *hh, u32 *i,
					 const s64 *mix_constant,
					 const u8 *mullo_mask)
{
	u8 *tmp = alloc_mem_block(i);
	if (!tmp) {
		return;
	}

	bpf_mm256_srli_epi64((s64 *)(tmp), (const s64 *)(hh), 23);
	bpf_mm256_xor_si256((u8 *)(hh), (u8 *)(hh), tmp);
	bpf_mm256_mullo_epi64_emulated((s64 *)(hh), (const s64 *)(hh),
				       mix_constant, i, mullo_mask);
	bpf_mm256_srli_epi64((s64 *)(tmp), (const s64 *)(hh), 47);
	bpf_mm256_xor_si256((u8 *)(hh), (const u8 *)(hh), tmp);
}

static inline void test_bpf_fasthash32_alt_avx2_pkt5_in_bpf(void)
{
	struct pkt_5tuple pkt = { PACKET_ATTRS };
	u32 seeds[8] = { SEEDx8 };

	u32 i = 0, j = 0;
	u32 *dest = alloc_mem_block(&i);
	u32 *mm_times_13 = alloc_mem_block(&i);
	u32 *mm = alloc_mem_block(&i);
	u32 *mix_constant = alloc_mem_block(&i);
	u32 *mullo_mask = alloc_mem_block(&i);
	if (!dest || !mm_times_13 || !mm || !mullo_mask || !mix_constant) {
		return;
	}

	bpf_mm256_set1_epi64x((s64 *)mm, M);
	bpf_mm256_set1_epi64x((s64 *)mm_times_13, M * 13);
	bpf_mm256_set1_epi64x((s64 *)mix_constant, 0x2127599bf4325c37ULL);
#pragma clang unroll loop
	for (j = 0; j < 4; j++) {
		mullo_mask[j * 2] = 0;
		mullo_mask[j * 2 + 1] = 0xffffffff;
	}

	log_info(
		"bpf_fasthash32_alt_avx2_pkt5() (BPF implementation) test started\n");

	const u64 *pos = (const u64 *)&pkt;
	const unsigned char *pos2;

	u32 *hh = (u32 *)dest;
	bpf_mm256_xor_si256((u8 *)hh, (u8 *)seeds, (u8 *)mm_times_13);

	u32 *vv = alloc_mem_block(&i);
	if (!vv) {
		return;
	}

	bpf_mm256_set1_epi64x((s64 *)vv, *pos++);
	bpf_fasthash_mix_avx2((u8 *)vv, &i, (const s64 *)mix_constant,
			      (const u8 *)mullo_mask);
	bpf_mm256_xor_si256((u8 *)hh, (u8 *)hh, (u8 *)vv);

	pos2 = (const unsigned char *)pos;
	bpf_mm256_set1_epi64x((s64 *)vv, 0);

	u32 *tmp = alloc_mem_block(&i);
	if (!tmp) {
		return;
	}

	bpf_mm256_set1_epi64x((s64 *)tmp, (u64)pos2[4] << 32);
	bpf_mm256_xor_si256((u8 *)vv, (u8 *)vv, (u8 *)tmp);
	bpf_mm256_set1_epi64x((s64 *)tmp, (u64)pos2[3] << 24);
	bpf_mm256_xor_si256((u8 *)vv, (u8 *)vv, (u8 *)tmp);
	bpf_mm256_set1_epi64x((s64 *)tmp, (u64)pos2[2] << 16);
	bpf_mm256_xor_si256((u8 *)vv, (u8 *)vv, (u8 *)tmp);
	bpf_mm256_set1_epi64x((s64 *)tmp, (u64)pos2[1] << 8);
	bpf_mm256_xor_si256((u8 *)vv, (u8 *)vv, (u8 *)tmp);
	bpf_mm256_set1_epi64x((s64 *)tmp, (u64)pos2[0]);
	bpf_mm256_xor_si256((u8 *)vv, (u8 *)vv, (u8 *)tmp);
	bpf_fasthash_mix_avx2((u8 *)vv, &i, (const s64 *)mix_constant,
			      (const u8 *)mullo_mask);
	bpf_mm256_xor_si256((u8 *)hh, (u8 *)hh, (u8 *)vv);
	bpf_mm256_mullo_epi64_emulated((s64 *)hh, (const s64 *)hh,
				       (const s64 *)mm, &i,
				       (const u8 *)mullo_mask);

	bpf_fasthash_mix_avx2((u8 *)hh, &i, (const s64 *)mix_constant,
			      (const u8 *)mullo_mask);

	for (int i = 0; i < 8; i++) {
		log_debug("dest[%d] = 0x%x\n", i, dest[i]);
	}

	log_info(
		"bpf_fasthash32_alt_avx2_pkt5() (BPF implementation) test passed\n");
}

static inline void test_bpf_simd_low_level_ops(void)
{
	log_info("bpf SIMD low level ops test started\n");

	u8 a[32] = { 0 }, b[32] = { 0 }, c[32] = { 0 };

	bpf_kernel_fpu_begin();
	bpf_mm256_xor_si256(c, a, b);
	bpf_kernel_fpu_end();

	log_info("bpf SIMD low level ops test passed\n");
}

static inline void test_bpf_crc32c(void)
{
	log_info("bpf_crc32c() test started\n");

	struct pkt_5tuple pkt = { PACKET_ATTRS };
	u32 crc_bpf = 0, crc_kernel = 0;

	crc_bpf = crc32c(&pkt, sizeof(pkt), 0xdeadbeef);
	crc_kernel = bpf_crc32c_sse(&pkt, sizeof(pkt), 0xdeadbeef);

	xdp_assert_eq(crc_bpf, crc_kernel,
		      "crc_bpf should be equal to crc_kernel");

	log_info("bpf_crc32c() test passed\n");
	return;

xdp_error:
	log_info("bpf_crc32c() test failed\n");
}

SEC("xdp") int xdp_main(struct xdp_md *ctx)
{
	test_bpf_xxh32_avx2_pkt5();
	test_bpf_xxh32_avx2_pkt5_pkts();
	test_bpf_fasthash32_avx2();
	test_bpf_fasthash32_alt_avx2();
	test_bpf_fasthash32_alt_avx2_pkt5();
	test_bpf_fasthash32_alt_avx2_pkt5_in_bpf();
	test_bpf_simd_low_level_ops();
	test_bpf_crc32c();

	return XDP_PASS;
}
