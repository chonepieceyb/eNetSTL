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

#define SS_KEY_SIZE 16
/* TODO: Update SS_KEY_SIZE to match sizeof(ss_key_t) */

#define SS_COUNT_SIZE sizeof(ss_count_t)
/* Currently SS_COUNT_SIZE must be 2 for SIMD implementation to work */

struct ss {
	ss_key_t keys[SS_NUM_COUNTERS];
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
#if SS_KEY_SIZE == 16
	return bpf_k16_cmp_eq(key1, SS_KEY_SIZE, key2, SS_KEY_SIZE);
#elif SS_KEY_SIZE == 32
	return bpf_k32_cmp_eq(key1, SS_KEY_SIZE, key2, SS_KEY_SIZE);
#else
#error unsupported SS_KEY_SIZE for HyperCom (SIMD) implementation
#endif
}

static inline int ss_increment(struct ss *tbl, const ss_key_t *key)
{
	ss_count_t min_count = tbl->counts[0];
	u32 min_idx = 0, i;
	int ret = 0;

	for (i = 0; i < SS_NUM_COUNTERS; i++) {
		if (__ss_key_cmp(tbl->keys + i, key) == 0) {
			ss_log(debug, "found matching key at %d, count = %d", i,
			       tbl->counts[i]);

			tbl->counts[i]++;
			goto out;
		}
	}

	/* This is also responsible for inserting new keys when the table is not full,
     * since the counts are initialized to 0.
     */
	min_idx = bpf_find_min_u16_sse(tbl->counts);
	/* This bound check actually does not alter min_idx */
	asm_bound_check(min_idx, SS_NUM_COUNTERS);
	min_count = tbl->counts[min_idx];

	ss_log(debug, "replacing (or inserting new) key at %d, count = %d",
	       min_idx, min_count);

	__builtin_memcpy(tbl->keys + min_idx, key, SS_KEY_SIZE);
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
