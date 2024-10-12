#include "../common.h"

#define BITMAP_TYPE
typedef __u64 bitmap_type;
#define PER_LONG_BITS_SHIFT 6
#define __ffs __ffs64
#define BITS_PER_LONG 64

#include "./sched_hpiq.h"
#include "./simple_ringbuf.h"

char _license[] SEC("license") = "GPL";

PACKET_COUNT_MAP_DEFINE

/***********************************************
*********************PKTBKT PERCPU**************
************************************************/

struct __packet_type {
	__u64 data;
};

DECLARE_SIMPLE_RINGBUF(pkt_bkt, struct __packet_type, PKT_BKT_SIZE_SHIFT)
DECLARE_HPIQ(cffs, 1, bitmap_type)

struct cffs_piq {
	struct hpiq__cffs hpiq[2];
	bool prime;
	__u32 h_index;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct simple_rbuf__pkt_bkt);
	__uint(max_entries, 2 * BUCKET_NUM);
} pkt_buf_percpu_map SEC(".maps");

static __inline int cffs_enqueue(struct cffs_piq *cffs, void *bucket_buffer_map,
				 __u32 prio, const struct __packet_type *pkt)
{
	__u32 bktnum = prio;
	if (unlikely(prio >= (cffs->h_index + 2 * BUCKET_NUM))) {
		bktnum = cffs->h_index + 2 * BUCKET_NUM - 1;
	} else if (unlikely(prio < cffs->h_index)) {
		bktnum = cffs->h_index;
	}

	bktnum -=
		cffs->h_index; //bounded to [0, 2 * BUCKET_NUM], real prio is h_index + prio

	//prime:True used_prime:True => True, prime:True, use_prime:False => False. prime:False, use_prime:True => False, prime: False, use_prime:False => True
	bool use_prime = (bktnum < BUCKET_NUM);
	bool idx = !(use_prime ^ cffs->prime);
	__u32 __bktnum = bktnum - (!(use_prime)) * BUCKET_NUM;
	int key = idx * BUCKET_NUM + __bktnum;

	log_debug("bktnum : %u", bktnum);
	log_debug("__bucket_num: %u", __bktnum);
	log_debug("hindex: %u", cffs->h_index);
	log_debug("use prime :%d, current prime: %d, cal idx :%d", use_prime,
		  cffs->prime, idx);
	log_debug("percpu bkt key: %d", key);

	struct simple_rbuf__pkt_bkt *pktbuf;
	pktbuf = bpf_map_lookup_elem(bucket_buffer_map, &key);
	if (pktbuf == NULL)
		return -1;
	//insert the packet to bucket ringbuf
	struct __packet_type *prod = pkt_bkt__simple_rbuf_prod(pktbuf);
	if (prod == NULL)
		return -2; //ring buffer is full
	asm_bound_check(idx, 2); //to make the verifier happy
	hpiq_insert__cffs(&cffs->hpiq[idx], __bktnum);
	log_debug("cffs_enqueue: prime hpiq first level: %x",
		  cffs->hpiq[idx].bitmap_lvl_1);
	__builtin_memcpy(prod, pkt, sizeof(*prod));
	pkt_bkt__simple_rbuf_submit(pktbuf);
	return 0;
}

static __inline struct simple_rbuf__pkt_bkt *
cffs_first_bkt(struct cffs_piq *cffs, void *bucket_buffer_map, __u32 *bktnum)
{
	bool prime = cffs->prime;
	asm_bound_check(prime, 2);
	struct hpiq__cffs *phpiq = &cffs->hpiq[prime];
	if (unlikely(phpiq->bitmap_lvl_1) == 0) {
		struct hpiq__cffs *snd_hpiq = &cffs->hpiq[!prime];
		if (snd_hpiq->bitmap_lvl_1 == 0) {
			//non packet
			log_debug("cffs is empty");
			return NULL;
		} else {
			//switch the primary
			log_debug("cffs_first_bkt: switch primary");
			cffs->prime = !(prime);
			cffs->h_index += BUCKET_NUM;
			phpiq = snd_hpiq;
		}
	}
	log_debug("cffs_first_bkt: current prime: %d", cffs->prime);
	__u32 __bktnum = (__u32)hpiq_front_idx__cffs(phpiq);
	log_debug("cffs_first_bkt: front bkt %u", __bktnum);
	int key = (int)cffs->prime * BUCKET_NUM + (int)(__bktnum);
	*bktnum = __bktnum;
	return bpf_map_lookup_elem(bucket_buffer_map, &key);
}

static __inline void cffs_dequeue(struct cffs_piq *cffs,
				  struct simple_rbuf__pkt_bkt *bucket_buffer,
				  __u32 bktnum)
{
	/*bktnum is the retparam of cffs_first_bkt it should come from the primary hffs and should not be empty 
        * 1. unset hffs 
        * 2. consume ringbuffer 
        */
	bool prime = cffs->prime;
	asm_bound_check(prime, 2);
	hpiq_delete__cffs(&cffs->hpiq[prime], bktnum);
	if (unlikely(cffs->hpiq[prime].bitmap_lvl_1 == 0)) {
		//switch prime
		bool snd = !prime;
		asm_bound_check(snd, 2);
		if (cffs->hpiq[snd].bitmap_lvl_1 != 0) {
			cffs->prime = !(prime);
			cffs->h_index += BUCKET_NUM;
		}
	}
	pkt_bkt__simple_rbuf_release(bucket_buffer);
}

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct cffs_piq);
	__uint(max_entries, 1);
} cffs_piq_map SEC(".maps");

SEC("xdp")
int test_hffs1(struct xdp_md *ctx)
{
	//test insert
	int key = 0, res;
	struct cffs_piq *cffs;
	struct simple_rbuf__pkt_bkt *pktbuf;
	struct simple_rbuf__pkt_bkt *pktbuf2;
	cffs = bpf_map_lookup_elem(&cffs_piq_map, &key);
	if (cffs == NULL) {
		log_error("failed to get cffs map");
		goto xdp_error;
	}
	__u32 prio = bpf_get_prandom_u32() % BUCKET_NUM;
	struct __packet_type pkt = { .data = (__u64)prio };
	log_debug("test insert prio %u", prio);
	res = cffs_enqueue(cffs, (void *)&pkt_buf_percpu_map, prio, &pkt);
	log_debug("cffs_enqueue res %d", res);
	xdp_assert_eq(0, res, "cffs enqueue failed");
	log_info("test1 success");

	//get the pkt right now
	__u32 bktnum = 0;
	pktbuf = cffs_first_bkt(cffs, (void *)&pkt_buf_percpu_map, &bktnum);
	log_debug("cffs_first_bkt, bktnum: %u", bktnum);
	xdp_assert_eq(0, cffs->h_index, "cffs_first_bkt hindex is not correct");
	xdp_assert((pktbuf != NULL), "cffs_first_bkt return NULL");

	//get ringbuffer
	struct __packet_type *__pkt;
	__pkt = pkt_bkt__simple_rbuf_cons(pktbuf);
	xdp_assert((__pkt != NULL), "cffs first bucket ringbuffer is empty");
	xdp_assert_eq(pkt.data, __pkt->data, "pkt is not the same");
	log_debug("cffs_first_bkt, hindex: %u", cffs->h_index);
	log_info("test2 success");

	//update the second prio in [BUCKET_NUM, 2*BUCKET_NUM)
	__u32 prio2 = (bpf_get_prandom_u32() % BUCKET_NUM) + BUCKET_NUM;
	struct __packet_type pkt2 = { .data = (__u64)prio2 };
	res = cffs_enqueue(cffs, (void *)&pkt_buf_percpu_map, prio2, &pkt2);
	xdp_assert_eq(0, res, "cffs enqueue2 fail");
	log_info("test3 success");

	//dequeue the first one
	cffs_dequeue(cffs, pktbuf, bktnum);
	xdp_assert((pkt_bkt__simple_rbuf_empty(pktbuf)),
		   "ring buffer not empty");
	xdp_assert_eq(1, cffs->prime, "prime not switch");
	log_info("test4 success");

	//lookup the current front
	//get the pkt right now
	__u32 bktnum2 = 0;
	pktbuf2 = cffs_first_bkt(cffs, (void *)&pkt_buf_percpu_map, &bktnum2);
	log_debug("cffs_first_bkt2, bktnum2: %u", bktnum2);
	log_debug("cffs_first_bkt2, hindex: %u", cffs->h_index);
	xdp_assert_eq(1, cffs->prime, "prime is not correct");
	xdp_assert_eq(BUCKET_NUM, cffs->h_index, "hindex is not correct");
	xdp_assert((pktbuf2 != NULL), "cffs_first_bkt2 return NULL");
	xdp_assert_eq((prio2 - BUCKET_NUM), bktnum2, "prio2 not correct");
	struct __packet_type *__pkt2;
	__pkt2 = pkt_bkt__simple_rbuf_cons(pktbuf2);
	xdp_assert((__pkt2 != NULL), "cffs first bucket2 ringbuffer is empty");
	xdp_assert_eq(pkt2.data, __pkt2->data, "pkt2 is not the same");
	log_info("test5 success");
	log_info("test all success");
	return XDP_PASS;
xdp_error:;
	//log_error("res: %d", res);
	return XDP_DROP;
}

SEC("xdp")
int test_hffs2(struct xdp_md *ctx)
{
	int key = 0, res;
	struct cffs_piq *cffs;
	cffs = bpf_map_lookup_elem(&cffs_piq_map, &key);
	if (cffs == NULL) {
		log_error("failed to get cffs map");
		goto xdp_error;
	}
	//enquene
	__u32 prio1 = bpf_get_prandom_u32() % (2 * BUCKET_NUM) + cffs->h_index;
	__u32 prio2 = bpf_get_prandom_u32() % (2 * BUCKET_NUM) + cffs->h_index;

	__u32 min_prio = min(prio1, prio2);
	__u32 max_prio = max(prio1, prio2);

	log_debug("prio1: %u", prio1);
	log_debug("prio2: %u", prio2);
	struct __packet_type pkt1 = { .data = (__u64)prio1 };
	struct __packet_type pkt2 = { .data = (__u64)prio2 };
	res = cffs_enqueue(cffs, (void *)&pkt_buf_percpu_map, prio1, &pkt1);
	xdp_assert_eq(0, res, "cffs enqueue1 failed");
	res = cffs_enqueue(cffs, (void *)&pkt_buf_percpu_map, prio2, &pkt2);
	xdp_assert_eq(0, res, "cffs enqueue2 failed");

	//dequeue1
	__u32 bktnum = 0;
	struct __packet_type *__pkt;
	struct simple_rbuf__pkt_bkt *pktbuf;

	pktbuf = cffs_first_bkt(cffs, (void *)&pkt_buf_percpu_map, &bktnum);
	xdp_assert((pktbuf != NULL), "cffs_first_bkt1 return NULL");

	__pkt = pkt_bkt__simple_rbuf_cons(pktbuf);
	xdp_assert((__pkt != NULL), "cffs first bucket1 ringbuffer is empty");
	xdp_assert_eq(min_prio, __pkt->data, "not the pkt with min prio");
	log_info("test1 success");

	cffs_dequeue(cffs, pktbuf, bktnum);

	pktbuf = cffs_first_bkt(cffs, (void *)&pkt_buf_percpu_map, &bktnum);
	xdp_assert((pktbuf != NULL), "cffs_first_bkt2 return NULL");

	__pkt = pkt_bkt__simple_rbuf_cons(pktbuf);
	xdp_assert((__pkt != NULL), "cffs first bucket2 ringbuffer is empty");
	xdp_assert_eq(max_prio, __pkt->data, "not the pkt with max prio");
	log_info("test2 success");

	cffs_dequeue(cffs, pktbuf, bktnum);
	return XDP_PASS;

xdp_error:
	return XDP_DROP;
}

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	LATENCY_START_TIMESTAMP_DEFINE

	int key = 0, res;
	struct cffs_piq *cffs;
	struct simple_rbuf__pkt_bkt *pktbuf;
	cffs = bpf_map_lookup_elem(&cffs_piq_map, &key);
	if (cffs == NULL) {
		goto xdp_error;
	}
	//enquene
	__u32 prio = 10;
	struct __packet_type pkt = { .data = (__u64)prio };
	res = cffs_enqueue(cffs, (void *)&pkt_buf_percpu_map, prio, &pkt);

	//dequeue
	__u32 bktnum = 0;
	pktbuf = cffs_first_bkt(cffs, (void *)&pkt_buf_percpu_map, &bktnum);
	if (pktbuf == NULL) {
		goto xdp_error;
	}

	struct __packet_type *__pkt;
	__pkt = pkt_bkt__simple_rbuf_cons(pktbuf);
	cffs_dequeue(cffs, pktbuf, bktnum);

	PACKET_COUNT_MAP_UPDATE
#ifdef LATENCY_EXP
	SWAP_MAC_AND_RETURN_XDP_TX(ctx) 
#endif
	return XDP_DROP;
xdp_error:
	log_error("xdp_error");
	return XDP_DROP;
}

SEC("xdp")
int xdp_ffs_insert(struct xdp_md *ctx)
{
	int key = 0;
	struct cffs_piq *cffs;
	cffs = bpf_map_lookup_elem(&cffs_piq_map, &key);
	if (cffs == NULL) {
		goto xdp_error;
	}
	struct hpiq__cffs *hffs;
	hffs = &cffs->hpiq[0];
	//enquene
	__u32 prio = 10;
	hpiq_insert__cffs(hffs, prio);
	return XDP_DROP;
xdp_error:
	log_error("xdp_error");
	return XDP_DROP;
}