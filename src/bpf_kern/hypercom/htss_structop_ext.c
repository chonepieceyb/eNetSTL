/*
 * @author chonepieceyb
 * testing BPF_STRUCT_OP for my st_demo 
 */
#include "../common.h"
#include <bpf/bpf_tracing.h>
#include "../fasthash.h"

#define ST_DEMO_OPS_NAME_MAX 16 

char _license[] SEC("license") = "GPL";

/* static vars */
#define MAX_ENTRY 2048
#define HASH_SEED_1 0xdeadbeef
#define HASH_SEED_2 0xaaaabbbb
#define MEMBER_NO_MATCH 0
#define MEMBER_MAX_PUSHES 8

/* datastruct params */
#define NUM_ENTRIES 1024
#define NUM_BUCKETS 128
#define SIZE_BUCKET_T 32
#define BUCKET_MASK 127
#define MEMBER_BUCKET_ENTRIES 8

typedef __u16 sig_t;
typedef __u16 set_t;

struct htss_key_type {
	char data[13];
};

struct member_ht_bucket {
  sig_t sigs[MEMBER_BUCKET_ENTRIES];
  set_t sets[MEMBER_BUCKET_ENTRIES];
};

struct htss_memory {
	struct member_ht_bucket buckets[NUM_BUCKETS];
};

struct mod_struct_ops_ctx {
  // lookup res
  int res;
  rwlock_t rw_lock;
};

struct htss_struct_ops {
  int (*htss_loop_up_eBPF)(struct mod_struct_ops_ctx *ctx);
  int (*htss_update_eBPF)(struct mod_struct_ops_ctx *ctx);
  struct module *owner;
};

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
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct htss_memory);
	__uint(max_entries, 1);
	// __uint(pinning, 1);
} htss_memory_map SEC(".maps");

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
static __always_inline void get_buckets_index(struct htss_key_type *key,
					      __u32 key_len, __u32 *prim_bkt,
					      __u32 *sec_bkt, sig_t *sig)
{
	/* 和vbf一样，计算两个hash值，其中 h1 = hash(key) h2 = hash(hash(key)) */
#if DESIGN_PATTERN_TEST == 0
	__u32 first_hash = fasthash32(key, key_len, HASH_SEED_1);
	__u32 sec_hash = fasthash32(&first_hash, sizeof(__u32), HASH_SEED_2);
#else
	__u32 first_hash = 0xdeadbeef;
	__u32 sec_hash = 0xaaaabbbb;
#endif

	if (prim_bkt == NULL || sec_bkt == NULL || sig == NULL) {
		return;
	}
	*sig = first_hash;
	*prim_bkt = sec_hash & BUCKET_MASK;
	*sec_bkt = (*prim_bkt ^ *sig) & BUCKET_MASK;
}

static __always_inline int try_insert(struct member_ht_bucket *buckets,
				      __u32 prim, __u32 sec, sig_t sig,
				      set_t set_id)
{
	int i;
	/* If not full then insert into one slot */
	for (i = 0; i < MEMBER_BUCKET_ENTRIES; i++) {
		if (buckets[prim].sets[i] == MEMBER_NO_MATCH) {
			buckets[prim].sigs[i] = sig;
			buckets[prim].sets[i] = set_id;
			return 0;
		}
	}
	/* If prim failed, we need to access second bucket */
	for (i = 0; i < MEMBER_BUCKET_ENTRIES; i++) {
		if (buckets[sec].sets[i] == MEMBER_NO_MATCH) {
			buckets[sec].sigs[i] = sig;
			buckets[sec].sets[i] = set_id;
			return 0;
		}
	}
	return -1;
}

int __always_inline
make_space_bucket_non_recur(struct member_ht_bucket *buckets, __u32 bkt_idx,
			    unsigned int *nr_pushes, sig_t tmp_sig,
			    set_t set_id, struct pushed_array *__pushed_array,
			    struct record_array *__record_array)
{
	__u32 curr_bkt_idx = bkt_idx;

	/* clear stack memory */
	for (int i = 0; i < NUM_BUCKETS; i++) {
		for (int j = 0; j < MEMBER_BUCKET_ENTRIES; j++) {
			__pushed_array->data[i][j] = 0;
		}
	}

	for (int i = 0; i < MEMBER_MAX_PUSHES; i++) {
		__record_array->data[i].bkt_idx = 0;
		__record_array->data[i].set_idx = 0;
	}

	struct record *push_record = __record_array->data;

	int have_space_flag = 0;
	__u32 initial_set_id = 0;
	// p用来记录踢出的次数，也就是递归次数
	int p;
	for (p = 0; p < MEMBER_MAX_PUSHES; p++) {
		/* 遍历第一次选出的桶的所有位置的sig，找出一个下一个位置为空的，将其移到下一个 */
		unsigned int i, j;
		struct member_ht_bucket *next_bkt[MEMBER_BUCKET_ENTRIES];
		asm_bound_check(curr_bkt_idx, NUM_BUCKETS);
		struct member_ht_bucket *curr_bkt = &buckets[curr_bkt_idx];
		uint32_t next_bucket_idx;
		/* i: 当前bucket的set id, j: 下一个bucket的set id */
		for (i = 0; i < MEMBER_BUCKET_ENTRIES; i++) {
			sig_t curr_sig = curr_bkt->sigs[i];
			next_bucket_idx = (curr_sig ^ curr_bkt_idx) &
					  BUCKET_MASK;
			next_bkt[i] = &buckets[next_bucket_idx];
			for (j = 0; j < MEMBER_BUCKET_ENTRIES; j++) {
				if (next_bkt[i]->sets[j] == MEMBER_NO_MATCH)
					break;
			}
			if (j != MEMBER_BUCKET_ENTRIES) {
				have_space_flag = 1;
				break;
			}
		}
		/* 下一个桶中有空位 */
		if (i != MEMBER_BUCKET_ENTRIES) {
			// 记录当前的桶和位置(入栈)
			push_record[p].bkt_idx = curr_bkt_idx;
			push_record[p].set_idx = i;
			p = (p + 1) &
			    (MEMBER_MAX_PUSHES -
			     1); /* 这里为了过验证的修改导致MEMBER_MAX_PUSHES必须为2的幂 */
			push_record[p].bkt_idx = next_bucket_idx;
			push_record[p].set_idx = j;
			break; // 跳出整个循环，结束递归寻找空间
		} else {
			/* 下一个桶没有空位，需要选择当前桶中一个没有被踢出过的元素，将其踢出到下一个桶中，并继续下一轮大循环，直到找到空位置 */
			for (i = 0; i < MEMBER_BUCKET_ENTRIES; i++) {
				if (__pushed_array->data[curr_bkt_idx][i] ==
				    0) {
					push_record[p].bkt_idx = curr_bkt_idx;
					push_record[p].set_idx = i;
					if (p == 0) {
						initial_set_id = i;
					}
					__pushed_array->data[curr_bkt_idx][i] =
						1;
					curr_bkt_idx = (curr_bkt->sigs[i] ^
							curr_bkt_idx) &
						       BUCKET_MASK;
					;
					break;
				}
			}
			if (i == MEMBER_BUCKET_ENTRIES) {
				return -ENOSPC;
			}
		}
	}
	/* 踢出次数超过最大踢出次数后，仍找不到空位置，返回插入错误 */
	if (p == MEMBER_MAX_PUSHES && have_space_flag == 0) {
		// printf("add to bucket %d hit max push(hit max_push)\n", bkt_idx);
		return -ENOSPC;
	} else {
		/* 逆序遍历递归记录(出栈)，将所有的记录的位置的元素都移动到下一个桶 */
		for (int c = p; c > 0; c--) {
			if (c >= MEMBER_MAX_PUSHES || c < 0) {
				goto error;
			}
			if (push_record[c].bkt_idx >= NUM_BUCKETS ||
			    push_record[c].set_idx >= MEMBER_BUCKET_ENTRIES) {
				goto error;
			}
			struct record curr_record = push_record[c];
			struct record prev_record = push_record[c - 1];
			asm_bound_check(curr_record.bkt_idx, NUM_BUCKETS);
			asm_bound_check(prev_record.bkt_idx, NUM_BUCKETS);
			asm_bound_check(curr_record.set_idx,
					MEMBER_BUCKET_ENTRIES);
			asm_bound_check(prev_record.set_idx,
					MEMBER_BUCKET_ENTRIES);
			buckets[curr_record.bkt_idx].sigs[curr_record.set_idx] =
				buckets[prev_record.bkt_idx]
					.sigs[prev_record.set_idx];
			buckets[curr_record.bkt_idx].sets[curr_record.set_idx] =
				buckets[prev_record.bkt_idx]
					.sets[prev_record.set_idx];
		}
		/* 赋值本次add待插入的元素 */
		struct record first_record = push_record[0];
		asm_bound_check(first_record.bkt_idx, NUM_BUCKETS);
		asm_bound_check(first_record.set_idx, MEMBER_BUCKET_ENTRIES);
		buckets[first_record.bkt_idx].sets[first_record.set_idx] =
			set_id;
		buckets[first_record.bkt_idx].sigs[first_record.set_idx] =
			tmp_sig;

		return initial_set_id;
	}
error:
	return -ENOSPC;
}

static __always_inline int
search_bucket_single(__u32 bucket_id, sig_t tmp_sig,
		     struct member_ht_bucket *buckets, set_t *set_id)
{
	asm_bound_check(bucket_id, NUM_BUCKETS);
	__u32 iter;
	for (iter = 0; iter < MEMBER_BUCKET_ENTRIES; iter++) {
		if (tmp_sig == buckets[bucket_id].sigs[iter] && buckets[bucket_id].sets[iter] != MEMBER_NO_MATCH) {
			*set_id = buckets[bucket_id].sets[iter];
			return 1;
		}
	}
not_found:
	return 0;
}


SEC("struct_ops/htss_loop_up_eBPF")
int BPF_PROG(bpf_htss_loop_up_eBPF, struct mod_struct_ops_ctx *c, struct htss_key_type *key)
{
	__u32 zero = 0;
	set_t set_id = MEMBER_NO_MATCH;
	int ret = 0;

	struct htss_memory *__htss = bpf_map_lookup_elem(&htss_memory_map, &zero);
	if (__htss == NULL) {
		goto finish;
	}
	
	struct member_ht_bucket *buckets = __htss->buckets;
	if (buckets == NULL) {
		ret = -1;
		goto finish;
	}

	__u32 prim_bucket_idx = 0, sec_bucket_idx = 0;
	sig_t tmp_sig = 0;

	get_buckets_index(key, sizeof(struct htss_key_type), &prim_bucket_idx,
			  &sec_bucket_idx, &tmp_sig);

	asm_bound_check(prim_bucket_idx, NUM_BUCKETS);
	struct member_ht_bucket prim_bkt = buckets[prim_bucket_idx];

	if (search_bucket_single(prim_bucket_idx, tmp_sig, buckets, &set_id) ||
	    search_bucket_single(sec_bucket_idx, tmp_sig, buckets, &set_id))
		ret = 1;

finish:
	return ret;
}

SEC("struct_ops/htss_update_eBPF")
int BPF_PROG(bpf_htss_update_eBPF, struct mod_struct_ops_ctx *c, struct htss_key_type *key, set_t set_id)
{
	int ret = 0;
	unsigned int nr_pushes = 0;
	__u32 prim_bucket = 0;
	__u32 sec_bucket = 0;
	sig_t tmp_sig = 0;
	set_t flag_mask = 1U << (sizeof(set_t) * 8 - 1);
	__u32 zero = 0;
	__u32 index = 0;

	struct htss_memory *__htss = bpf_map_lookup_elem(&htss_memory_map, &zero);
	if (__htss == NULL) {
		goto finish;
	}
	struct member_ht_bucket *buckets = __htss->buckets;

	/* get stack memory pointer */
	struct pushed_array *__pushed_array =
		bpf_map_lookup_elem(&pushed_map, &index);
	if (__pushed_array == NULL) {
		goto finish;
	}
	struct record_array *__record_array =
		bpf_map_lookup_elem(&record_map, &index);
	if (__record_array == NULL) {
		goto finish;
	}


	get_buckets_index(key, sizeof(struct htss_key_type), &prim_bucket,
			  &sec_bucket, &tmp_sig);

	ret = try_insert(buckets, prim_bucket, sec_bucket, tmp_sig, set_id);
	if (ret != -1) {
		goto finish;
	}

	/* Random pick prim or sec for recursive displacement */
	__u32 select_bucket = (tmp_sig && 1U) ? prim_bucket : sec_bucket;

	ret = make_space_bucket_non_recur(buckets, select_bucket, &nr_pushes,
					  tmp_sig, set_id, __pushed_array,
					  __record_array);
	if (ret >= 0) {
		ret = 1;
	}
finish:
	return ret;
}

SEC(".struct_ops")
struct htss_struct_ops htss_struct_op = {
	.htss_loop_up_eBPF     = (void *)bpf_htss_loop_up_eBPF,
	.htss_update_eBPF     = (void *)bpf_htss_update_eBPF,
};