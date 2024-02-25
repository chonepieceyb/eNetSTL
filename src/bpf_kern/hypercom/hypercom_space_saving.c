#include "../vmlinux.h"

#include "../common.h"
#include "../bpf_cmp_alg_simd.h"

#define ss_log(level, fmt, ...)                                         \
	log_##level(" space_saving (hypercom): " fmt " (%s @ line %d)", \
		    ##__VA_ARGS__, __func__, __LINE__)

#define inline inline __attribute__((always_inline))

struct pkt_5tuple_with_pad {
	struct pkt_5tuple pkt;
	__u8 pad[3];
} __attribute__((packed));

typedef struct pkt_5tuple_with_pad ss_key_t;
typedef u16 ss_count_t;

#define SS_NUM_COUNTERS 8
#if SS_NUM_COUNTERS % 8 != 0
#error currently SS_NUM_COUNTERS must be a multiple of 8 for SIMD implementation to work
#endif

#define SS_KEY_SIZE sizeof(ss_key_t)
/* Currently SS_KEY_SIZE must be a multiple of 4 for SIMD implementation to work */

#define SS_COUNT_SIZE sizeof(ss_count_t)
/* Currently SS_COUNT_SIZE must be 2 for SIMD implementation to work */

struct ss {
	u8 keys[SS_KEY_SIZE * SS_NUM_COUNTERS];
	ss_count_t counts[SS_NUM_COUNTERS];
	ss_count_t overestimates[SS_NUM_COUNTERS];
};

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct ss);
} ss_map SEC(".maps");

static inline struct ss *ss_get_table(void)
{
	struct ss *tbl;
	u32 zero = 0;
	tbl = bpf_map_lookup_elem(&ss_map, &zero);
	return tbl;
}

static inline int __ss_memcmp(const void *s1, const void *s2, size_t n)
{
	const uint8_t *p1 = s1, *p2 = s2;
	int ret = 0;

	while (n--) {
		if ((ret = *p1++ - *p2++) != 0)
			break;
	}
	return ret;
}

static inline int __ss_key_cmp(const ss_key_t *key1, const ss_key_t *key2)
{
	return __ss_memcmp(key1, key2, SS_KEY_SIZE);
}

static inline int ss_increment(struct ss *tbl, const ss_key_t *key)
{
	ss_count_t min_count = tbl->counts[0];
	u32 min_idx = 0, i, blk_idx, mask;
	int ret = 0;

	for (i = 0; i < SS_NUM_COUNTERS; i += 8) {
		mask = ~0;

		for (blk_idx = 0; blk_idx < SS_KEY_SIZE / 4; ++blk_idx) {
			mask &= bpf__find_mask_u32_avx(
				(const u32 *)tbl->keys +
					blk_idx * SS_NUM_COUNTERS + i,
				((const u32 *)key)[blk_idx]);
			if (mask == 0) {
				goto replace_or_insert;
			}
		}

		i += bpf_tzcnt_u32(mask) >> 2;
		/* This bound check actually does not alter i */
		asm_bound_check(i, SS_NUM_COUNTERS);
		ss_log(debug,
		       "found matching key (with SIMD) at %d, count = %d", i,
		       tbl->counts[i]);
		tbl->counts[i]++;
		goto out;
	}

	/* This is also responsible for inserting new keys when the table is not full,
     * since the counts are initialized to 0.
     */
replace_or_insert:
	min_idx =
		bpf__find_min_u16_sse(tbl->counts, SS_NUM_COUNTERS, &min_count);
	/* This bound check actually does not alter min_idx */
	asm_bound_check(min_idx, SS_NUM_COUNTERS);

	ss_log(debug, "replacing (or inserting new) key at %d, count = %d",
	       min_idx, min_count);

	for (blk_idx = 0; blk_idx < SS_KEY_SIZE / 4; ++blk_idx) {
		((u32 *)tbl->keys)[blk_idx * SS_NUM_COUNTERS + min_idx] =
			((const u32 *)key)[blk_idx];
	}
	tbl->overestimates[min_idx] = min_count;
	tbl->counts[min_idx] = min_count + 1;
	ret = 0;

out:
	return ret;
}

SEC("xdp") int xdp_main(struct xdp_md *ctx)
{
	struct hdr_cursor nh;
	void *data_end;
	struct pkt_5tuple_with_pad pkt;
	struct ss *tbl;
	int ret;

	nh.pos = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	ret = parse_pkt_5tuple(&nh, data_end, &pkt.pkt);
	if (unlikely(ret != 0)) {
		ss_log(error, "failed to parse packet 5-tuple: %d", ret);
		goto out;
	} else {
		ss_log(debug,
		       "pkt: src_ip=0x%08x src_port=0x%04x dst_ip=0x%08x dst_port=0x%04x proto=0x%02x",
		       pkt.pkt.src_ip, pkt.pkt.src_port, pkt.pkt.dst_ip,
		       pkt.pkt.dst_port, pkt.pkt.proto);
	}

	tbl = ss_get_table();
	if (unlikely(tbl == NULL)) {
		ss_log(error, "failed to get space saving table");
		goto out;
	}

	ret = ss_increment(tbl, &pkt);
	if (unlikely(ret != 0)) {
		ss_log(error, "failed to update space saving table: %d", ret);
		goto out;
	} else {
		ss_log(debug, "successfully updated space saving table");
	}

out:
	return XDP_DROP;
}
