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
#define MEMBER_LOOKUP_VBF(key, key_len, set_id)		\
	j, h1, h2;																			\
	bit_loc;																				\
	mask = ~0;																			\
	h1 = jhash(&key, key_len, HASH_SEED_1);					\
	h2 = jhash(&h1, sizeof(h1), HASH_SEED_2);				\
	for (j = 0; j < NUM_HASHES; j++) {							\
		bit_loc = (h1 + j * h2) & BIT_MASK;						\
		mask &= test_bit(bit_loc);										\
	}																								\
	if (mask) {																			\
		set_id = ctz32(mask) + 1;											\
		log_info("key %d founded, set_id: %d\n", key, set_id);\
	} else {																				\
		set_id = MEMBER_NO_MATCH;											\
		log_info("key %d not founded, set_id: %d\n", key, set_id);							\
	}																								\

#define MEMBER_ADD_VBF(key, key_len, set_id)			\
	i, h1, h2;																			\
	bit_loc;																				\
	if (set_id > NUM_SET || set_id == MEMBER_NO_MATCH)	\
		return -1;																		\
	h1 = jhash(&key, key_len, HASH_SEED_1);					\
	h2 = jhash(&h1, sizeof(h1), HASH_SEED_2);				\
	for (i = 0; i < NUM_HASHES; i++) {							\
		bit_loc = (h1 + i * h2) & BIT_MASK;						\
		set_bit(bit_loc, set_id);											\
	}																								\

/* core malloc area */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, __u32);  
	__uint(max_entries, MAX_ENTRY);
} map SEC(".maps");

/* vBF helper implementation */
inline __u32
test_bit(__u32 bit_loc)
{
	__u32 n = NUM_SET;
	/*
	 * a is how many bits in one BF are represented by one 32bit
	 * variable.
	 */
	__u32 a = 32 >> MUL_SHIFT;
	/*
	 * x>>b is the divide, x & (a-1) is the mod, & (1<<n-1) to mask out bits
	 * we do not need
	 */
	__u32 key = bit_loc >> DIV_SHIFT;

	const __u32 *value = bpf_map_lookup_elem(&map, &key);
	// log_info("testbit() lookup key: %x\n", key);
	if (value == NULL) {
		// log_error("bpf_map_lookup_elem failed at line: %d\n", __LINE__);
		return -1;
	}
	__u32 value_new = *value;
	// log_info("test_bit() value_new: %u\n", value_new);
	return (value_new >> (((bit_loc & (a - 1)) << MUL_SHIFT))) & ((1ULL << n) - 1);
}

inline void
set_bit(__u32 bit_loc, __s32 set)
{
	__u32 a = 32 >> MUL_SHIFT;
	__u32 key = 0;
	key = bit_loc >> DIV_SHIFT;
	__u32 *value = bpf_map_lookup_elem(&map, &key);
	__u32 value_new;
	if (value == NULL) {
		// log_error("bpf_map_lookup_elem failed at line: %d\n", __LINE__);
		value_new = 0;
	} else {
		value_new = *value;
	}
	value_new |= 1UL << (((bit_loc & (a - 1)) << MUL_SHIFT) + set - 1);
	bpf_map_update_elem(&map, &key, &value_new, BPF_ANY);
}

/* vBF API implementation */
static __always_inline int
member_lookup_vbf(__u32 *key, __u32 key_len, __s32 *set_id)
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
		mask &= test_bit(bit_loc);
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
member_add_vbf(__u32 *key, __u32 key_len, __s32 set_id)
{
	__u32 i, h1, h2;
	__u32 bit_loc;

	if (set_id > NUM_SET || set_id == MEMBER_NO_MATCH)
		return -1;

	h1 = jhash(key, key_len, HASH_SEED_1);
	h2 = jhash(&h1, sizeof(__u32), HASH_SEED_2);

	for (i = 0; i < NUM_HASHES; i++) {
		bit_loc = (h1 + i * h2) & BIT_MASK;
		set_bit(bit_loc, set_id);
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

	for (int k = 10; k < 20; k += 2) {
		MEMBER_ADD_VBF(k, key_len, set_id)
		// member_add_vbf(&i, key_len, set_id);
	}
	for (int v = 10; v < 20; v++) {
		MEMBER_LOOKUP_VBF(v, key_len, set_id)
		// member_lookup_vbf(&v, key_len, &set_id);
	}
	return XDP_PASS;
}
