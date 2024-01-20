#include "vmlinux.h"
#include "bpf_helpers.h"
#include "common.h"
#include "jhash.h"
#include "xxhash.h"
#include "fasthash.h"

char _license[] SEC("license") = "GPL";

#define __TARGET_ARCH_x86
#include <bpf/bpf_tracing.h>

/* static vars */
#define MAX_ENTRY 2048
#define HASH_SEED_1 0xdeadbeef
#define HASH_SEED_2 0xaaaabbbb
#define MEMBER_NO_MATCH 0

#define EINVAL 1
#define ENOSPC 2
/* datastruct params */
#define NUM_KEYS 1000
#define NUM_SET 8
#define NUM_KEYS_PER_BF 125
#define BITS 2048
#define BIT_MASK 2047
#define NUM_HASHES 4
#define MUL_SHIFT 3
#define DIV_SHIFT 2

#define TEST_RANGE 20
/* set to 1 enable design pattern test, it will replace the kfunc to constant operation */
#define DESIGN_PATTERN_TEST 0
/* bitwise operation */
static inline __u32
ctz32(__u32 v)
{
	v = v - (v&(v-1));
	return ( ( (v & 0xFFFF0000 ) != 0 ? ( v &= 0xFFFF0000, 16) : 0) | ( ( v& 0xFF00FF00 ) != 0 ? ( v &= 0xFF00FF00, 8 ) : 0 ) | ( ( v & 0xF0F0F0F0) != 0 ? ( v &= 0xF0F0F0F0, 4 ) : 0 ) 
	| ( ( v & 0xCCCCCCCC ) != 0 ? ( v &= 0xCCCCCCCC, 2 ) : 0 ) | ( ( v & 0xAAAAAAAA ) != 0 ) );
}

/* core malloc area */
typedef __u16 set_t;
struct vbf_memory {
	__u32 table[MAX_ENTRY]
};
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct vbf_memory);  
	__uint(max_entries, 1);
	__uint(pinning, 1);
} vbf_memory_map SEC(".maps");

/* vBF helper implementation */
static __always_inline __u32
test_bit(__u32 *table, __u32 bit_loc)
{
	if ((bit_loc >> DIV_SHIFT) >= MAX_ENTRY) {
		log_error("exceed max entry count at %d, bit_loc >> DIV_SHIFT: %d \n", __LINE__ ,bit_loc >> DIV_SHIFT);
		return -EINVAL;
	}
	__u32 a = 32 >> MUL_SHIFT;
	return (table[bit_loc >> DIV_SHIFT] >>
			((bit_loc & (a - 1)) << MUL_SHIFT)) & ((1ULL << NUM_SET) - 1);
}

static __always_inline void
set_bit(__u32 *table, __u32 bit_loc, __s32 set)
{
	if ((bit_loc >> DIV_SHIFT) >= MAX_ENTRY) {
		log_error("exceed max entry count at %d, bit_loc >> DIV_SHIFT: %d \n", __LINE__ ,bit_loc >> DIV_SHIFT);
		return;
	}
	__u32 a = 32 >> MUL_SHIFT;
	table[bit_loc >> DIV_SHIFT] |=
			1UL << (((bit_loc & (a - 1)) << MUL_SHIFT) + set - 1);
}

/* vBF API implementation */
static int
member_lookup_vbf(__u32 *table, struct pkt_5tuple *key, __u32 key_len, set_t *set_id)
{
#if DESIGN_PATTERN_TEST == 0
	__u32 h1 = fasthash32(key, key_len, HASH_SEED_1);
	__u32 h2 = fasthash32(&h1, sizeof(__u32), HASH_SEED_2);
#else 
	__u32 h1 = key->src_ip;
	__u32 h2 = key->dst_ip;
#endif
	__u32 mask = ~0;
	__u32 bit_loc;

	__u32 j;
	for (j = 0; j < NUM_HASHES; j++) {
		bit_loc = (h1 + j * h2) & BIT_MASK;
		mask &= test_bit(table, bit_loc);
	}

#if DESIGN_PATTERN_TEST != 0
	// force execute ctz32 to test performance
	mask |= 0x00100000;
#endif
	if (mask) {
#if DESIGN_PATTERN_TEST == 0
		*set_id = ctz32(mask) + 1;
#else 
		*set_id = (set_t)mask;
#endif
		return 1;
	} else {
		*set_id = MEMBER_NO_MATCH;
		return 0;
	}
}

static int
member_add_vbf(__u32 *table, struct pkt_5tuple *key, __u32 key_len, set_t set_id)
{
	__u32 i, h1, h2;
	__u32 bit_loc;

	if (set_id > NUM_SET || set_id == MEMBER_NO_MATCH)
		return -1;

	h1 = fasthash32(key, key_len, HASH_SEED_1);
	h2 = fasthash32(&h1, sizeof(__u32), HASH_SEED_2);

	for (i = 0; i < NUM_HASHES; i++) {
		bit_loc = (h1 + i * h2) & BIT_MASK;
		set_bit(table, bit_loc, set_id);
	}
	return 0;
}

/* test program */
SEC("xdp")
int test_vbf(struct xdp_md *ctx) {

	set_t set_id = 1;
	__u32 key_len = sizeof(__u32);
	__u32 i, j, h1, h2;
	__u32 bit_loc;
	__u32 mask;

	int zero = 0;
	struct vbf_memory *__vbf = bpf_map_lookup_elem(&vbf_memory_map, &zero);
	if (__vbf == NULL) {
		log_error("memory initialization error at line %d\n", __LINE__);
		return XDP_PASS;
	}
	__u32 *table = __vbf->table;

	struct pkt_5tuple pkt = {0};
	__u8 add_res[TEST_RANGE] = {0};
	__u8 lookup_res[TEST_RANGE] = {0};

	for (int i = 1; i < TEST_RANGE; i += 2) {
		pkt.src_ip = i;
		pkt.dst_ip = i;
		pkt.src_port = i;
		pkt.dst_port = i;
		pkt.proto = 0x04;
		add_res[i] = member_add_vbf(table, &pkt, sizeof(struct pkt_5tuple), set_id);
		if (add_res[i] == 0) {
			log_info("add %d success\n", i);
		} else {
			log_error("add %d failed\n", i);
		}
	}

	for (int i = 1; i < 20; i++) {
		pkt.src_ip = i;
		pkt.dst_ip = i;
		pkt.src_port = i;
		pkt.dst_port = i;
		pkt.proto = 0x04;
		lookup_res[i] = member_lookup_vbf(table, &pkt, sizeof(struct pkt_5tuple), &set_id);
		if (lookup_res[i] == 1) {
			log_info("lookup %d success, set_id: %d\n", i, set_id);
		}
	}
	return XDP_DROP;
}

/* exp setup program */
SEC("xdp")
int add_data(struct xdp_md *ctx) {
	set_t set_id = 1;
	int zero = 0;
	struct vbf_memory *__vbf = bpf_map_lookup_elem(&vbf_memory_map, &zero);
	if (unlikely(__vbf == NULL)) {
		log_error("memory initialization error at line %d\n", __LINE__);
		goto finish;
	}
	__u32 *table = __vbf->table;

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

	int add_res = member_add_vbf(table, &pkt, sizeof(struct pkt_5tuple), set_id);
	if (add_res != 0) {
		log_error("add failed\n");
	}
finish:
	return XDP_DROP;
}

/* exp program */
SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
	set_t set_id = 1;
	int zero = 0;
	struct vbf_memory *__vbf = bpf_map_lookup_elem(&vbf_memory_map, &zero);
	if (unlikely(__vbf == NULL)) {
		log_error("memory initialization error at line %d\n", __LINE__);
		goto finish;
	}
	__u32 *table = __vbf->table;

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

	// member_add_vbf(table, &pkt, sizeof(struct pkt_5tuple), set_id);
	int lookup_res = member_lookup_vbf(table, &pkt, sizeof(struct pkt_5tuple), &set_id);

finish:
	return XDP_DROP;
}