#include "../vmlinux.h"
#include "../common.h"
#include "../jhash.h"
#include "../fasthash.h"

char _license[] SEC("license") = "GPL";

#define __TARGET_ARCH_x86
#include <bpf/bpf_tracing.h>

PACKET_COUNT_MAP_DEFINE

/* static vars */
#define MAX_ENTRY 2048
#define HASH_SEED_1 0xdeadbeef
#define HASH_SEED_2 0xaaaabbbb
#define MEMBER_NO_MATCH 0
#define MEMBER_MAX_PUSHES 16

#define EINVAL 1
#define ENOSPC 2
/* datastruct params */
#define NUM_ENTRIES 1024
#define NUM_BUCKETS 128
#define SIZE_BUCKET_T 32
#define BUCKET_MASK 127
#define MEMBER_BUCKET_ENTRIES 16

/* set to 1 enable design pattern test, it will replace the kfunc to constant operation */
#define DESIGN_PATTERN_TEST 1
#define TEST_RANGE 20
/* core malloc aera */
typedef __u16 sig_t;
typedef __u16 set_t;
struct member_ht_bucket {
	sig_t sigs[MEMBER_BUCKET_ENTRIES];
	set_t sets[MEMBER_BUCKET_ENTRIES];
};
struct htss_memory {
	struct member_ht_bucket buckets[NUM_BUCKETS];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct htss_memory);
	__uint(max_entries, 1);
} htss_memory_map SEC(".maps");

struct record {
	__u32 bkt_idx;
	__u32 set_idx;
};

struct record_array {
	struct record data[MEMBER_MAX_PUSHES];
};

struct pushed_array {
	__u8 data[NUM_BUCKETS][MEMBER_BUCKET_ENTRIES];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct record_array);
	__uint(max_entries, 1);
} record_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct pushed_array);
	__uint(max_entries, 1);
} pushed_map SEC(".maps");

/* htss helper function */
static __always_inline void
get_buckets_index(struct pkt_5tuple *key, __u32 key_len, __u32 *prim_bkt, __u32 *sec_bkt, sig_t *sig)
{
	__u32 first_hash = fasthash32(key, key_len, HASH_SEED_1);
	__u32 sec_hash = fasthash32(&first_hash, sizeof(__u32), HASH_SEED_2);

	if (prim_bkt == NULL || sec_bkt == NULL || sig == NULL) {
		log_error("error at line %d", __LINE__);
		return;
	}
	*sig = first_hash;
	*prim_bkt = sec_hash & BUCKET_MASK;
	*sec_bkt =  (*prim_bkt ^ *sig) & BUCKET_MASK;

}

static __always_inline int
search_bucket_single1(__u32 bucket_id, sig_t tmp_sig,
		struct member_ht_bucket *buckets,
		set_t *set_id)
{
	asm_bound_check(bucket_id, NUM_BUCKETS);
	__u32 iter;

#define LOOP_NUM_1 16
	for (iter = 0; iter < LOOP_NUM_1; iter++) {
		if (tmp_sig == buckets[bucket_id].sigs[iter] && buckets[bucket_id].sets[iter] != MEMBER_NO_MATCH) {
			*set_id = buckets[bucket_id].sets[iter];
			return 1;
		}
	}
not_found:
	return 0;
}

static __always_inline int
search_bucket_single2(__u32 bucket_id, sig_t tmp_sig,
		struct member_ht_bucket *buckets,
		set_t *set_id)
{
	asm_bound_check(bucket_id, NUM_BUCKETS);
	__u32 iter;

	#define LOOP_NUM_2 0
	for (iter = 0; iter < LOOP_NUM_2; iter++) {
		if (tmp_sig == buckets[bucket_id].sigs[iter] && buckets[bucket_id].sets[iter] != MEMBER_NO_MATCH) {
			*set_id = buckets[bucket_id].sets[iter];
			return 1;
		}
	}
not_found:
	return 0;
}

/* htss API implementation */
static int
member_lookup_ht(struct member_ht_bucket *buckets, struct pkt_5tuple *key, set_t *set_id)
{
	__u32 prim_bucket_idx = 0, sec_bucket_idx = 0;
	sig_t tmp_sig = 0;

	if (set_id == NULL || buckets == NULL) {
		log_error("error at line %d\n", __LINE__);
		goto not_found;
	}
	*set_id = MEMBER_NO_MATCH;
	get_buckets_index(key, sizeof(struct pkt_5tuple), &prim_bucket_idx, &sec_bucket_idx, &tmp_sig);

	if (search_bucket_single1(prim_bucket_idx, tmp_sig, buckets, set_id) 
			|| search_bucket_single2(sec_bucket_idx, tmp_sig, buckets, set_id))
		return 1;

not_found:
	return 0;
}

/* exp program */
SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
	LATENCY_START_TIMESTAMP_DEFINE

	__u32 zero = 0;
	set_t set_id = 1;
	struct htss_memory* __htss = bpf_map_lookup_elem(&htss_memory_map, &zero);
	if (__htss == NULL) {
		log_error("error at line %d\n", __LINE__);
		goto finish;
	}
	struct member_ht_bucket *buckets = __htss->buckets;

	struct pkt_5tuple pkt;
	void *data, *data_end;
	struct hdr_cursor nh;
	int ret;

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	nh.pos = data;
	if (unlikely((ret = parse_pkt_5tuple(&nh, data_end, &pkt)) != 0)) {
		log_error("cannot parse packet: %d", ret);
		goto finish;
	} else {
		log_debug(
			"pkt: src_ip=0x%08x src_port=0x%04x dst_ip=0x%08x dst_port=0x%04x proto=0x%02x",
			pkt.src_ip, pkt.src_port, pkt.dst_ip,
			pkt.dst_port, pkt.proto);
	}

	int res = member_lookup_ht(buckets, &pkt, &set_id);

	PACKET_COUNT_MAP_UPDATE
#ifdef LATENCY_EXP
	SWAP_MAC_AND_RETURN_XDP_TX(ctx) 
#endif
finish:
	return XDP_DROP;
}