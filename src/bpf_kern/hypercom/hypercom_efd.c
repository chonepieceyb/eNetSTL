#include "../vmlinux.h"
#include "../common.h"

#include "../bpf_hash_alg_simd.h"

#define efd_log(level, fmt, ...)                                              \
	log_##level(" efd (hypercom): " fmt " (%s @ line %d)", ##__VA_ARGS__, \
		    __func__, __LINE__)

#define EFD_CHUNK_NUM_GROUPS 64
#define EFD_CHUNK_NUM_BINS 256
#define EFD_VALUE_NUM_BITS 8
#define EFD_CHUNK_NUM_BIN_TO_GROUP_SETS \
	(EFD_CHUNK_NUM_BINS / EFD_CHUNK_NUM_GROUPS)
#define EFD_LOOKUPTBL_SHIFT (32 - 4)

#define EFD_KEY_SIZE (sizeof(struct pkt_5tuple_with_pad))

#define EFD_HASH(key, table) \
	(uint32_t)(bpf_crc32c_sse(key, EFD_KEY_SIZE, 0xbc9f1d34))
#define EFD_HASHFUNCA(key, table) \
	(uint32_t)(bpf_crc32c_sse(key, EFD_KEY_SIZE, 0xbc9f1d35))
#define EFD_HASHFUNCB(key, table) \
	(uint32_t)(bpf_crc32c_sse(key, EFD_KEY_SIZE, 0xbc9f1d36))

#if (EFD_VALUE_NUM_BITS == 8 || EFD_VALUE_NUM_BITS == 16 || \
     EFD_VALUE_NUM_BITS == 24 || EFD_VALUE_NUM_BITS == 32)
#define EFD_LOAD_SI128(val) _mm_load_si128(val)
#else
#define EFD_LOAD_SI128(val) _mm_lddqu_si128(val)
#endif

#define EFD_TARGET_GROUP_NUM_RULES (22)
#define EFD_TARGET_CHUNK_NUM_RULES \
	(EFD_CHUNK_NUM_GROUPS * EFD_TARGET_GROUP_NUM_RULES)

#define EFD_MAX_NUM_RULES 2816
#define EFD_NUM_CHUNKS_SHIFT 1
#define EFD_NUM_CHUNKS 2
#if (1 << EFD_NUM_CHUNKS_SHIFT) != EFD_NUM_CHUNKS
#error EFD_NUM_CHUNKS_SHIFT is not consistent with EFD_NUM_CHUNKS
#endif
#if (EFD_NUM_CHUNKS * EFD_TARGET_CHUNK_NUM_RULES) < EFD_MAX_NUM_RULES
#error EFD_NUM_CHUNKS_SHIFT is too small
#endif

typedef uint16_t efd_lookuptbl_t;
typedef uint16_t efd_hashfunc_t;

#if (EFD_VALUE_NUM_BITS > 0 && EFD_VALUE_NUM_BITS <= 8)
typedef uint8_t efd_value_t;
#elif (EFD_VALUE_NUM_BITS > 8 && EFD_VALUE_NUM_BITS <= 16)
typedef uint16_t efd_value_t;
#elif (EFD_VALUE_NUM_BITS > 16 && EFD_VALUE_NUM_BITS <= 32)
typedef uint32_t efd_value_t;
#else
#error("EFD_VALUE_NUM_BITS must be in the range [1:32]")
#endif

#define inline inline __attribute__((always_inline))

struct efd_online_group_entry {
	efd_hashfunc_t hash_idx[EFD_VALUE_NUM_BITS];
	efd_lookuptbl_t lookup_table[EFD_VALUE_NUM_BITS];
} __attribute__((packed));

struct efd_online_chunk {
	uint8_t bin_choice_list[(EFD_CHUNK_NUM_BINS * 2 + 7) / 8];
	struct efd_online_group_entry groups[EFD_CHUNK_NUM_GROUPS];
} __attribute__((packed));

struct efd_table {
	struct efd_online_chunk chunks[EFD_NUM_CHUNKS];
};

struct pkt_5tuple_with_pad {
	struct pkt_5tuple pkt;
	uint8_t __pad[3];
} __attribute__((packed));

static const uint32_t
	efd_bin_to_group[EFD_CHUNK_NUM_BIN_TO_GROUP_SETS][EFD_CHUNK_NUM_BINS] = {
		{ 0,  0,  0,  0,  1,  1,  1,  1,  2,  2,  2,  2,  3,  3,  3,
		  3,  4,  4,  4,  4,  5,  5,  5,  5,  6,  6,  6,  6,  7,  7,
		  7,  7,  8,  8,  8,  8,  9,  9,  9,  9,  10, 10, 10, 10, 11,
		  11, 11, 11, 12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14,
		  15, 15, 15, 15, 16, 16, 16, 16, 17, 17, 17, 17, 18, 18, 18,
		  18, 19, 19, 19, 19, 20, 20, 20, 20, 21, 21, 21, 21, 22, 22,
		  22, 22, 23, 23, 23, 23, 24, 24, 24, 24, 25, 25, 25, 25, 26,
		  26, 26, 26, 27, 27, 27, 27, 28, 28, 28, 28, 29, 29, 29, 29,
		  30, 30, 30, 30, 31, 31, 31, 31, 32, 32, 32, 32, 33, 33, 33,
		  33, 34, 34, 34, 34, 35, 35, 35, 35, 36, 36, 36, 36, 37, 37,
		  37, 37, 38, 38, 38, 38, 39, 39, 39, 39, 40, 40, 40, 40, 41,
		  41, 41, 41, 42, 42, 42, 42, 43, 43, 43, 43, 44, 44, 44, 44,
		  45, 45, 45, 45, 46, 46, 46, 46, 47, 47, 47, 47, 48, 48, 48,
		  48, 49, 49, 49, 49, 50, 50, 50, 50, 51, 51, 51, 51, 52, 52,
		  52, 52, 53, 53, 53, 53, 54, 54, 54, 54, 55, 55, 55, 55, 56,
		  56, 56, 56, 57, 57, 57, 57, 58, 58, 58, 58, 59, 59, 59, 59,
		  60, 60, 60, 60, 61, 61, 61, 61, 62, 62, 62, 62, 63, 63, 63,
		  63 },
		{ 34, 33, 48, 59, 0,  21, 36, 18, 9,  49, 54, 38, 51, 23, 31,
		  5,  44, 23, 37, 52, 11, 4,  58, 20, 38, 40, 38, 22, 26, 28,
		  42, 6,  46, 16, 31, 28, 46, 14, 60, 0,  35, 53, 16, 58, 16,
		  29, 39, 7,  1,  54, 15, 11, 48, 3,  62, 9,  58, 5,  30, 43,
		  17, 7,  36, 34, 6,  36, 2,  14, 10, 1,  47, 47, 20, 45, 62,
		  56, 34, 25, 39, 18, 51, 41, 61, 25, 56, 40, 41, 37, 52, 35,
		  30, 57, 11, 42, 37, 27, 54, 19, 26, 13, 48, 31, 46, 15, 12,
		  10, 16, 20, 43, 17, 12, 55, 45, 18, 8,  41, 7,  31, 42, 63,
		  12, 14, 21, 57, 24, 40, 5,  41, 13, 44, 23, 59, 25, 57, 52,
		  50, 62, 1,  2,  49, 32, 57, 26, 43, 56, 60, 55, 5,  49, 6,
		  3,  50, 46, 39, 27, 33, 17, 4,  53, 13, 2,  19, 36, 51, 63,
		  0,  22, 33, 59, 28, 29, 23, 45, 33, 53, 27, 22, 21, 40, 56,
		  4,  18, 44, 47, 28, 17, 4,  50, 21, 62, 8,  39, 0,  8,  15,
		  24, 29, 24, 9,  11, 48, 61, 35, 55, 43, 1,  54, 42, 53, 60,
		  22, 3,  32, 52, 25, 8,  15, 60, 7,  55, 27, 63, 19, 10, 63,
		  24, 61, 19, 12, 38, 6,  29, 13, 37, 10, 3,  45, 32, 32, 30,
		  49, 61, 44, 14, 20, 58, 35, 30, 2,  26, 34, 51, 9,  59, 47,
		  50 },
		{ 32, 35, 32, 34, 55, 5,  6,  23, 49, 11, 6,  23, 52, 37, 29,
		  54, 55, 40, 63, 50, 29, 52, 61, 25, 12, 56, 39, 38, 29, 11,
		  46, 1,  40, 11, 19, 56, 7,  28, 51, 16, 15, 48, 21, 51, 60,
		  31, 14, 22, 41, 47, 59, 56, 53, 28, 58, 26, 43, 27, 41, 33,
		  24, 52, 44, 38, 13, 59, 48, 51, 60, 15, 3,  30, 15, 0,  10,
		  62, 44, 14, 28, 51, 38, 2,  41, 26, 25, 49, 10, 12, 55, 57,
		  27, 35, 19, 33, 0,  30, 5,  36, 47, 53, 5,  53, 20, 43, 34,
		  37, 52, 41, 21, 63, 59, 9,  24, 1,  45, 24, 39, 44, 45, 16,
		  9,  17, 7,  50, 57, 22, 18, 28, 25, 45, 2,  40, 58, 15, 17,
		  3,  1,  27, 61, 39, 19, 0,  19, 21, 57, 62, 54, 60, 54, 40,
		  48, 33, 36, 37, 4,  42, 1,  43, 58, 8,  13, 42, 10, 56, 35,
		  22, 48, 61, 63, 10, 49, 9,  24, 9,  25, 57, 33, 18, 13, 31,
		  42, 36, 36, 55, 30, 37, 53, 34, 59, 4,  4,  23, 8,  16, 58,
		  14, 30, 11, 12, 63, 49, 62, 2,  39, 47, 22, 2,  60, 18, 8,
		  46, 31, 6,  20, 32, 29, 46, 42, 20, 31, 32, 61, 34, 4,  47,
		  26, 20, 43, 26, 21, 7,  3,  16, 35, 18, 44, 27, 62, 13, 23,
		  6,  50, 12, 8,  45, 17, 3,  46, 50, 7,  14, 5,  17, 54, 38,
		  0 },
		{ 29, 56, 5,  7,  54, 48, 23, 37, 35, 44, 52, 40, 33, 49, 60,
		  0,  59, 51, 28, 12, 41, 26, 2,  23, 34, 5,  59, 40, 3,  19,
		  6,  26, 35, 53, 45, 49, 29, 57, 28, 62, 58, 59, 19, 53, 59,
		  62, 6,  54, 13, 15, 48, 50, 45, 21, 41, 12, 34, 40, 24, 56,
		  19, 21, 35, 18, 55, 45, 9,  61, 47, 61, 19, 15, 16, 39, 17,
		  31, 3,  51, 21, 50, 17, 25, 25, 11, 44, 16, 18, 28, 14, 2,
		  37, 61, 58, 27, 62, 4,  14, 17, 1,  9,  46, 28, 37, 0,  53,
		  43, 57, 7,  57, 46, 21, 41, 39, 14, 52, 60, 44, 53, 49, 60,
		  49, 63, 13, 11, 29, 1,  55, 47, 55, 12, 60, 43, 54, 37, 13,
		  6,  42, 10, 36, 13, 9,  8,  34, 51, 31, 32, 12, 7,  57, 2,
		  26, 14, 3,  30, 63, 3,  32, 1,  5,  11, 27, 24, 26, 44, 31,
		  23, 56, 38, 62, 0,  40, 30, 6,  23, 38, 2,  47, 5,  15, 27,
		  16, 10, 31, 25, 22, 63, 30, 25, 20, 33, 32, 50, 29, 43, 55,
		  10, 50, 45, 56, 20, 4,  7,  27, 46, 11, 16, 22, 52, 35, 20,
		  41, 54, 46, 33, 42, 18, 63, 8,  22, 58, 36, 4,  51, 42, 38,
		  32, 38, 22, 17, 0,  47, 8,  48, 8,  48, 1,  61, 36, 33, 20,
		  24, 39, 39, 18, 30, 36, 9,  43, 42, 24, 10, 58, 4,  15, 34,
		  52 },
	};

static inline uint32_t efd_hash_empty(const void *key, const uint32_t len,
				      const uint32_t seed)
{
	return *(uint32_t *)key ^ seed;
}

static inline uint32_t efd_get_chunk_id(const struct efd_table *const table,
					const uint32_t hashed_key)
{
	return hashed_key & (EFD_NUM_CHUNKS - 1);
}

static inline uint32_t efd_get_bin_id(const struct efd_table *const table,
				      const uint32_t hashed_key)
{
	return (hashed_key >> EFD_NUM_CHUNKS_SHIFT) & (EFD_CHUNK_NUM_BINS - 1);
}

static inline void efd_compute_ids(const struct efd_table *const table,
				   const void *key, uint32_t *const chunk_id,
				   uint32_t *const bin_id)
{
	/* Compute the position of the entry in the hash table */
	uint32_t h = EFD_HASH(key, table);

	/* Compute the chunk_id where that entry can be found */
	*chunk_id = efd_get_chunk_id(table, h);
	asm_bound_check(*chunk_id, EFD_NUM_CHUNKS);

	/*
	 * Compute the bin within that chunk where the entry
	 * can be found (0 - 255)
	 */
	*bin_id = efd_get_bin_id(table, h);
	asm_bound_check(*bin_id, EFD_CHUNK_NUM_BINS);
}

static inline uint8_t efd_get_choice(const struct efd_table *const table,
				     const uint32_t chunk_id,
				     const uint32_t bin_id)
{
	const struct efd_online_chunk *chunk = &table->chunks[chunk_id];

	/*
	 * Grab the chunk (byte) that contains the choices
	 * for four neighboring bins.
	 */
	uint8_t choice_chunk =
		chunk->bin_choice_list[bin_id / EFD_CHUNK_NUM_BIN_TO_GROUP_SETS];

	/*
	 * Compute the offset into the chunk that contains
	 * the group_id lookup position
	 */
	int offset = (bin_id & 0x3) * 2;

	/* Extract from the byte just the desired lookup position */
	return (uint8_t)((choice_chunk >> offset) & 0x3);
}

extern efd_value_t
bpf_efd_lookup_internal_avx2(const efd_hashfunc_t *group_hash_idx,
			     const efd_lookuptbl_t *group_lookup_table,
			     const uint32_t hash_val_a,
			     const uint32_t hash_val_b) __ksym;

static inline efd_value_t
efd_lookup_internal_empty(const efd_hashfunc_t *group_hash_idx,
			  const efd_lookuptbl_t *group_lookup_table,
			  const uint32_t hash_val_a, const uint32_t hash_val_b)
{
	return (efd_value_t)hash_val_a;
}

static inline efd_value_t
efd_lookup_internal(const struct efd_online_group_entry *const group,
		    const uint32_t hash_val_a, const uint32_t hash_val_b)
{
	return bpf_efd_lookup_internal_avx2(
		group->hash_idx, group->lookup_table, hash_val_a, hash_val_b);
}

static inline efd_value_t efd_lookup_elem(const struct efd_table *table,
					  void *key)
{
	uint32_t chunk_id, group_id, bin_id;
	uint8_t bin_choice;
	const struct efd_online_group_entry *group;
	const struct efd_online_chunk *const chunks = table->chunks;

	/* Determine the chunk and group location for the given key */
	efd_compute_ids(table, key, &chunk_id, &bin_id);
	bin_choice = efd_get_choice(table, chunk_id, bin_id);
	group_id = efd_bin_to_group[bin_choice][bin_id];
	asm_bound_check(group_id, EFD_CHUNK_NUM_GROUPS);
	group = &chunks[chunk_id].groups[group_id];

	return efd_lookup_internal(group, EFD_HASHFUNCA(key, table),
				   EFD_HASHFUNCB(key, table));
}

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct efd_table);
} efd_table_map SEC(".maps");

static efd_value_t dummy __attribute__((used)) = 0;

char _license[] SEC("license") = "GPL";

SEC("xdp") int xdp_main(struct xdp_md *ctx)
{
	struct pkt_5tuple_with_pad pkt = { 0 };
	struct hdr_cursor nh = { .pos = (void *)(long)ctx->data };
	void *data_end = (void *)(long)ctx->data_end;
	struct efd_table *table;
	int ret, zero = 0;

	if (unlikely((ret = parse_pkt_5tuple(&nh, data_end, &pkt.pkt)) != 0)) {
		efd_log(error, "parse_pkt_5tuple failed: %d", ret);
		goto out;
	} else {
		efd_log(debug,
			"pkt: src_ip = 0x%08x, dst_ip = 0x%08x, src_port = 0x%04x, dst_port = 0x%04x, proto = 0x%02x",
			pkt.pkt.src_ip, pkt.pkt.dst_ip, pkt.pkt.src_port,
			pkt.pkt.dst_port, pkt.pkt.proto);
	}

	table = bpf_map_lookup_elem(&efd_table_map, &zero);
	if (unlikely(!table)) {
		efd_log(error, "bpf_map_lookup_elem failed");
		goto out;
	}

	dummy = efd_lookup_elem(table, &pkt);
	efd_log(debug, "test result = %d", dummy);

out:
	return XDP_DROP;
}
