#include "vmlinux.h"

#include "common.h"
#include "sk_common.h"
#include "sk_config.h"
#include "fasthash.h"
#include "xxhash.h"
#include "crc.h"
#include "bpf_hash_alg_simd.h"
#include "sk_cm.h"

// #define USE_EMULATED_HASH

#ifdef USE_CRC
#undef USE_CRC
#endif

#if HASHFN_N <= 2
#define USE_CRC
#endif

#define M 0x880355f21e6d1965ULL

_Static_assert((COLUMNS & (COLUMNS - 1)) == 0,
	       "COLUMNS must be a power of two");

static __u32 seeds[] = {
	0xec5853,  0xec5859,  0xec5861,	 0xec587f,  0xec58a7,  0xec58b3,
	0xec58c7,  0xec58d1,  0xec58531, 0xec58592, 0xec58613, 0xec587f4,
	0xec58a75, 0xec58b36, 0xec58c77, 0xec58d18, 0xec58539, 0xec58510,
	0xec58611, 0xec58712, 0xec58a13, 0xec58b14, 0xec58c15, 0xec58d16,
	0xec58521, 0xec58522, 0xec58623, 0xec58724, 0xec58a25, 0xec58b26,
	0xec58c27, 0xec58d28, 0xec58541, 0xec58542, 0xec58643, 0xec58744,
	0xec58a45, 0xec58b46, 0xec58c47, 0xec58d48, 0xec58551, 0xec58552,
	0xec58653, 0xec58754, 0xec58a55, 0xec58b56, 0xec58c57, 0xec58d58,
	0xec58561, 0xec58563, 0xec58663, 0xec58764, 0xec58a65, 0xec58b66,
	0xec58c67, 0xec58d68, 0xec58571, 0xec58572, 0xec58673, 0xec58774,
	0xec58a75, 0xec58b76, 0xec58c77, 0xec58d78,
};

char _license[] SEC("license") = "GPL";

struct countmin {
	__u32 values[HASHFN_N][COLUMNS];
};

struct mem_block {
	__u8 data[32];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct countmin);
	__uint(max_entries, 1);
} countmin SEC(".maps");

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

static inline void
bpf_fasthash32_alt_avx2_pkt5_emulated(const struct pkt_5tuple *data,
				      const u32 *seeds, u32 *dest)
{
	u32 i = 0, j = 0;
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

	const u64 *pos = (const u64 *)data;
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
}

static void __always_inline __countmin_hash_batch8(void *element, __u64 len,
						   __u32 *dest)
{
#if USE_IMPL == EBPF_IMPL
	for (int i = 0; i < HASHFN_N; i++) {
#ifdef USE_CRC
		dest[i] = crc32c(element, len, seeds[i]);
#elif USE_XXHASH
		dest[i] = xxh32(element, len, seeds[i]);
#else
		dest[i] = fasthash32(element, len, seeds[i]);
#endif /* USE_CRC */
	}
#elif USE_IMPL == EBPF_WITH_HYPERCOM_INTRINSIC_IMPL
#ifdef USE_CRC
	for (int i = 0; i < HASHFN_N; i++) {
		dest[i] = bpf_crc32c_sse(element, len, seeds[i]);
	}
#elif USE_XXHASH
#ifdef USE_EMULATED_HASH
#error xxHash implementation with SIMD intrinsic kfuncs is not supported
#else
	bpf_xxh32_avx2_pkt5(element, seeds, dest);
#endif /* USE_EMULATED_HASH */
#else
#ifdef USE_EMULATED_HASH
	bpf_fasthash32_alt_avx2_pkt5_emulated(element, seeds, dest);
#else
	bpf_fasthash32_alt_avx2_pkt5(element, seeds, dest);
#endif /* USE_EMULATED_HASH */
#endif /* USE_CRC */
#else
	log_error(" this should not happen");
#endif /* USE_IMPL */
}

static void __always_inline countmin_add(struct countmin *cm, void *element,
					 __u64 len)
{
	__u32 hashes[HASHFN_N], i, target_idx;

	__countmin_hash_batch8(element, len, hashes);
	for (i = 0; i < HASHFN_N; i++) {
		target_idx = hashes[i] & (COLUMNS - 1);
		NO_TEAR_ADD(cm->values[i][target_idx], 1);
	}
}

static void __always_inline countmin_add_hypercom(struct countmin *cm,
						  void *element, __u64 len)
{
	bpf_countmin_add_avx2_pkt5((struct pkt_5tuple *)element, seeds,
				   (u32 *)cm->values);
}

SEC("xdp") int xdp_main(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };
	struct pkt_5tuple pkt;
	uint32_t zero = 0;
	struct countmin *cm;
	int ret = 0;

	if ((ret = parse_pkt_5tuple(&nh, data_end, &pkt)) != 0) {
		log_error(" failed to parse packet: %d", ret);
		goto out;
	}

	cm = bpf_map_lookup_elem(&countmin, &zero);
	if (!cm) {
		log_error(" invalid entry in the countmin sketch");
		goto out;
	}

#if USE_IMPL == EBPF_IMPL || USE_IMPL == EBPF_WITH_HYPERCOM_INTRINSIC_IMPL
	countmin_add(cm, &pkt, sizeof(pkt));
#else
	countmin_add_hypercom(cm, &pkt, sizeof(pkt));
#endif

out:
	return XDP_DROP;
}
