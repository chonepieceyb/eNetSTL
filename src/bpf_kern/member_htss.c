#include "vmlinux.h"
#include "bpf_helpers.h"
#include "common.h"
#include "jhash.h"
#include "fasthash.h"

char _license[] SEC("license") = "GPL";

#define __TARGET_ARCH_x86
#include <bpf/bpf_tracing.h>

/* static vars */
#define MAX_ENTRY 2048
#define HASH_SEED_1 0xdeadbeef
#define HASH_SEED_2 0xaaaabbbb
#define MEMBER_NO_MATCH 0
#define MEMBER_MAX_PUSHES 8

#define EINVAL 1
#define ENOSPC 2
/* datastruct params */
#define NUM_ENTRIES 1024
#define NUM_BUCKETS 128
#define SIZE_BUCKET_T 32
#define BUCKET_MASK 127
#define MEMBER_BUCKET_ENTRIES 8

/* set to 1 enable design pattern test, it will replace the kfunc to constant operation */
#define DESIGN_PATTERN_TEST 0
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
	struct bpf_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct htss_memory);
	__uint(max_entries, 1);
	__uint(pinning, 0);
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

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct pkt_count);
	__uint(max_entries, 40);
	__uint(pinning, 1);
} count_map SEC(".maps");

/* htss helper function */
static __always_inline void get_buckets_index(struct pkt_5tuple *key,
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
#if DESIGN_PATTERN_TEST == 0
	for (iter = 0; iter < MEMBER_BUCKET_ENTRIES; iter++) {
		if (tmp_sig == buckets[bucket_id].sigs[iter] && buckets[bucket_id].sets[iter] != MEMBER_NO_MATCH) {
			*set_id = buckets[bucket_id].sets[iter];
			return 1;
		}
	}
#else
	if (tmp_sig == buckets[bucket_id].sigs[iter] && buckets[bucket_id].sets[iter] != MEMBER_NO_MATCH) {
		*set_id = buckets[bucket_id].sets[iter];
		return 1;
	}
#endif
not_found:
	return 0;
}

/* htss API implementation */
// ret = 0 表示为找到，ret = 1 表示找到
static int member_lookup_ht(struct htss_memory *__htss, struct pkt_5tuple *key,
			    set_t *set_id)
{
	__u32 prim_bucket_idx = 0, sec_bucket_idx = 0;
	sig_t tmp_sig = 0;
	int ret = 0;

	bpf_spin_lock(&__htss->lock);
	struct member_ht_bucket *buckets = __htss->buckets;
	if (buckets == NULL) {
		ret = -1;
		goto finish;
	}

	if (set_id == NULL || buckets == NULL) {
		ret = -1;
		goto finish;
	}
	*set_id = MEMBER_NO_MATCH;
	get_buckets_index(key, sizeof(struct pkt_5tuple), &prim_bucket_idx,
			  &sec_bucket_idx, &tmp_sig);

	asm_bound_check(prim_bucket_idx, NUM_BUCKETS);
	struct member_ht_bucket prim_bkt = buckets[prim_bucket_idx];

	if (search_bucket_single(prim_bucket_idx, tmp_sig, buckets, set_id) ||
	    search_bucket_single(sec_bucket_idx, tmp_sig, buckets, set_id))
		ret = 1;

finish:
	bpf_spin_unlock(&__htss->lock);
	return ret;
}

static __always_inline int member_add_ht(struct htss_memory *__htss,
					 struct pkt_5tuple *key, set_t set_id)
{
	int ret = 0;
	unsigned int nr_pushes = 0;
	__u32 prim_bucket = 0;
	__u32 sec_bucket = 0;
	sig_t tmp_sig = 0;
	set_t flag_mask = 1U << (sizeof(set_t) * 8 - 1);

	__u32 index = 0;

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

	bpf_spin_lock(&__htss->lock);
	struct member_ht_bucket *buckets = __htss->buckets;
	if (buckets == NULL) {
		ret = -1;
		goto unlock;
	}

	if (set_id == MEMBER_NO_MATCH || (set_id & flag_mask) != 0) {
		ret = -1;
		goto unlock;
	}

	get_buckets_index(key, sizeof(struct pkt_5tuple), &prim_bucket,
			  &sec_bucket, &tmp_sig);

	ret = try_insert(buckets, prim_bucket, sec_bucket, tmp_sig, set_id);
	if (ret != -1) {
		goto unlock;
	}

	/* Random pick prim or sec for recursive displacement */
	__u32 select_bucket = (tmp_sig && 1U) ? prim_bucket : sec_bucket;

	ret = make_space_bucket_non_recur(buckets, select_bucket, &nr_pushes,
					  tmp_sig, set_id, __pushed_array,
					  __record_array);
	if (ret >= 0) {
		ret = 1;
	}
unlock:
	bpf_spin_unlock(&__htss->lock);
finish:
	return ret;
}

/* test program */
SEC("xdp")
int test_htss(struct xdp_md *ctx)
{
	__u32 zero = 0;
	__u32 set_id = 1;
	struct htss_memory *__htss = bpf_map_lookup_elem(&htss_memory_map, &zero);
	if (__htss == NULL) {
		log_error("error at line %d\n", __LINE__);
		goto finish;
	}
	struct member_ht_bucket *buckets = __htss->buckets;
	if (buckets == NULL) {
		log_error("error at line %d\n", __LINE__);
		goto finish;
	}

	__u32 curr_sig = 0;
	__u32 prim = 0, sec = 0;
	__u32 i = 0;

	__u8 add_res[TEST_RANGE] = { 0 };
	__u8 lookup_res[TEST_RANGE] = { 0 };
	__u32 add_count = 0;

	struct pkt_5tuple pkt = { 0 };
	for (i = 2; i < TEST_RANGE; i += 2) {
		pkt.src_ip = i;
		pkt.dst_ip = i;
		pkt.src_port = i;
		pkt.dst_port = i;
		pkt.proto = 0x04;
		int ret = member_add_ht(__htss, &pkt, i);
		if (ret >= 0) {
			log_info("add %d success\n", i);
			add_count++;
			add_res[i] = 1;
		} else {
			log_info("add %d failed\n", i);
		}
	}

	set_t set_id_res = 0;
	for (i = 2; i < TEST_RANGE; i += 1) {
		pkt.src_ip = i;
		pkt.dst_ip = i;
		pkt.src_port = i;
		pkt.dst_port = i;
		pkt.proto = 0x04;
		int ret = member_lookup_ht(__htss, &pkt, &set_id_res);
		if (ret == 1) {
			log_info("lookup %d success, set_id: %d\n", i,
				 set_id_res);
			lookup_res[i] = 1;
		}
	}

	// for (i = 2; i < TEST_RANGE; i += 1) {
	// 	if (add_res[i] != lookup_res[i]) {
	// 		log_info("error at %d, add_res: %d, lookup_res: %d", i, add_res[i], lookup_res[i]);
	// 	}
	// }
	log_info("--------------------space usability: %d/%d", add_count,
		 NUM_BUCKETS * MEMBER_BUCKET_ENTRIES);

	// for (int i = 0; i < NUM_BUCKETS; i++) {
	// 	for (int j = 0; j < MEMBER_BUCKET_ENTRIES; j++) {
	// 		log_info("bucket %d, set %d, sig: %x, set_id: %d", i, j,
	// 			 buckets[i].sigs[j], buckets[i].sets[j]);
	// 	}
	// }

finish:
	return XDP_DROP;
}
/* exp setup program */
SEC("xdp")
int add_data(struct xdp_md *ctx) {
	__u32 zero = 0;
	set_t set_id = 1;
	struct htss_memory *__htss = bpf_map_lookup_elem(&htss_memory_map, &zero);
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
			pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port,
			pkt.proto);
	}


	// member_add_ht(buckets, &pkt, set_id);

	int add_res = member_add_ht(buckets, &pkt,  set_id);
	if (add_res != 0) {
		log_error("add failed\n");
	}
finish:
	return XDP_DROP;
}


/* exp program */
SEC("xdp")
int xdp_main(struct xdp_md *ctx){
	__u32 zero = 0;
	set_t set_id = 1;
	struct htss_memory *__htss = bpf_map_lookup_elem(&htss_memory_map, &zero);
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
			pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port,
			pkt.proto);
	}

	u32 cpu_id = bpf_get_smp_processor_id();
	struct pkt_count *current_count = bpf_map_lookup_elem(&count_map, &cpu_id);
	if (current_count == NULL) {
		log_debug("current_count is null");
		goto finish;
	}
	// 在这里修改读写比例，当前为写/读 = 1/32
	int rw_ratio = 32;
	if(current_count->rx_count % rw_ratio == 0) {
		member_add_ht(buckets, &pkt, set_id);
	} else {
		member_lookup_ht(buckets, &pkt, &set_id);
	}
	// 纯读
	// member_lookup_ht(buckets, &pkt, &set_id);
	current_count->rx_count = current_count->rx_count + 1;
finish:
	return XDP_DROP;
}