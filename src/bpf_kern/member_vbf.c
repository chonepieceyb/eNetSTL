#include "vmlinux.h"
#include "bpf_helpers.h"
#include "common.h"
#include "jhash.h"

char _license[] SEC("license") = "GPL";

#define __TARGET_ARCH_x86
#include <bpf/bpf_tracing.h>

/* static vars */
#define MAX_ENTRY 32
#define HASH_SEED_1 0xdeadbeef
#define HASH_SEED_2 0xaaaabbbb
#define MEMBER_NO_MATCH 0

#define EINVAL 1
#define ENOSPC 2
/* datastruct params */
#define NUM_KEYS 100
#define NUM_SET 8
#define NUM_KEYS_PER_BF 13
#define BITS 256
#define BIT_MASK 255
#define NUM_HASHES 3
#define MUL_SHIFT 3
#define DIV_SHIFT 2

/* datastruct params which injected by userspace */
// __u32 num_keys;
// __u32 num_set;
// __u32 num_keys_per_bf;
// __u32 bits;
// __u32 bit_mask;
// __u32 num_hashes;
// __u32 mul_shift;
// __u32 div_shift;

/* bitwise operation */
static inline __u32
ctz32(__u32 v)
{
	v = v - (v&(v-1));
	return ( ( (v & 0xFFFF0000 ) != 0 ? ( v &= 0xFFFF0000, 16) : 0) | ( ( v& 0xFF00FF00 ) != 0 ? ( v &= 0xFF00FF00, 8 ) : 0 ) | ( ( v & 0xF0F0F0F0) != 0 ? ( v &= 0xF0F0F0F0, 4 ) : 0 ) 
	| ( ( v & 0xCCCCCCCC ) != 0 ? ( v &= 0xCCCCCCCC, 2 ) : 0 ) | ( ( v & 0xAAAAAAAA ) != 0 ) );
}

/* function macro */
#define MEMBER_LOOKUP_VBF(table, key, key_len, set_id)		\
	j, h1, h2;																			\
	bit_loc;																				\
	mask = ~0;																			\
	h1 = jhash(&key, key_len, HASH_SEED_1);					\
	h2 = jhash(&h1, sizeof(h1), HASH_SEED_2);				\
	for (j = 0; j < NUM_HASHES; j++) {							\
		bit_loc = (h1 + j * h2) & BIT_MASK;						\
		mask &= test_bit(table, bit_loc);										\
	}																								\
	if (mask) {																			\
		set_id = ctz32(mask) + 1;											\
		log_info("key %d founded, set_id: %d\n", key, set_id);\
	} else {																				\
		set_id = MEMBER_NO_MATCH;											\
		log_info("key %d not founded, set_id: %d\n", key, set_id);							\
	}																								\

#define MEMBER_ADD_VBF(table, key, key_len, set_id)			\
	i, h1, h2;																			\
	bit_loc;																				\
	if (set_id > NUM_SET || set_id == MEMBER_NO_MATCH)	\
		return -1;																		\
	h1 = jhash(&key, key_len, HASH_SEED_1);					\
	h2 = jhash(&h1, sizeof(h1), HASH_SEED_2);				\
	for (i = 0; i < NUM_HASHES; i++) {							\
		bit_loc = (h1 + i * h2) & BIT_MASK;						\
		set_bit(table, bit_loc, set_id);											\
	}																								\

/* core malloc area */
struct vbf_memory {
	__u32 table[MAX_ENTRY]
};
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct vbf_memory);  
	__uint(max_entries, 1);
} map SEC(".maps");

/* vBF helper implementation */
static __always_inline __u32
test_bit(__u32 *table, __u32 bit_loc)
{
	if ((bit_loc >> DIV_SHIFT) >= MAX_ENTRY) {
		/* when lookup failed, will heat this */
		log_debug("bit_loc error");
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
		log_error("bit_loc error");
		return;
	}
	__u32 a = 32 >> MUL_SHIFT;
	table[bit_loc >> DIV_SHIFT] |=
			1UL << (((bit_loc & (a - 1)) << MUL_SHIFT) + set - 1);
}

/* vBF API implementation */
static __always_inline int
member_lookup_vbf(__u32 *table, __u32 *key, __u32 key_len, __s32 *set_id)
{
	__u32 j;
	if (key == NULL || set_id == NULL) {
		return 0;
	}
	__u32 h1 = jhash(key, key_len, HASH_SEED_1);
	__u32 h2 = jhash(&h1, key_len, HASH_SEED_2);
	__u32 mask = ~0;
	__u32 bit_loc;

	for (j = 0; j < NUM_HASHES; j++) {
		bit_loc = (h1 + j * h2) & BIT_MASK;
		mask &= test_bit(table, bit_loc);
	}

	if (mask) {
		*set_id = ctz32(mask) + 1;
		log_info("key %d founded, set_id: %d\n", key, set_id);
		return 1;
	} else {
		*set_id = MEMBER_NO_MATCH;
		log_info("key %d not founded, set_id: %d\n", key, set_id);
		return 0;
	}
}

static __always_inline int
member_add_vbf(__u32 *table, __u32 *key, __u32 key_len, __s32 set_id)
{
	__u32 i, h1, h2;
	__u32 bit_loc;

	if (set_id > NUM_SET || set_id == MEMBER_NO_MATCH)
		return -1;

	h1 = jhash(key, key_len, HASH_SEED_1);
	h2 = jhash(&h1, sizeof(__u32), HASH_SEED_2);

	for (i = 0; i < NUM_HASHES; i++) {
		bit_loc = (h1 + i * h2) & BIT_MASK;
		set_bit(table, bit_loc, set_id);
	}
	return 0;
}

/* test program */
SEC("xdp")
int test_vbf(struct xdp_md *ctx) {

	__s32 set_id = 1;
	__u32 key_len = sizeof(__u32);
	__u32 i, j, h1, h2;
	__u32 bit_loc;
	__u32 mask;

	int index = 0;
	struct vbf_memory *__vbf = bpf_map_lookup_elem(&map, &index);
	if (__vbf == NULL) {
		log_error("memory initialization error");
		return XDP_PASS;
	}
	__u32 *table = __vbf->table;

	for (int k = 10; k < 20; k += 2) {
		MEMBER_ADD_VBF(table, k, key_len, set_id)
		// member_add_vbf(table, &i, key_len, set_id);
	}
	for (int v = 10; v < 20; v++) {
		MEMBER_LOOKUP_VBF(table, v, key_len, set_id)
		// member_lookup_vbf(table, &v, key_len, &set_id);
	}
	return XDP_PASS;
}
