#include "../common.h"
#include "../sched_hpiq.h"
#include "../simple_ringbuf.h"
#include "../bpf_experimental.h"

char _license[] SEC("license") = "GPL";

#define CPU_CORES 40

#define FRONT_TAIL_BIT_POS 0 //bit pos, set means front
#define INS_LOOK_BIT_POS 1 //bit pos, set means insert

#define bktlist_lookup_flag(ins_look, front_tail)                \
	({                                                       \
		u32 __flags = 0;                                 \
		u32 __ins_look = !!(ins_look);                   \
		u32 __front_tail = !!(front_tail);               \
		__flags |= (__ins_look << INS_LOOK_BIT_POS);     \
		__flags |= (__front_tail << FRONT_TAIL_BIT_POS); \
	})

#define bktlist_delete_flag(front_tail)                          \
	({                                                       \
		u32 __flags = 0;                                 \
		u32 __front_tail = !!(front_tail);               \
		__flags |= (__front_tail << FRONT_TAIL_BIT_POS); \
	})

#define bktlist_flag_lookup_front bktlist_lookup_flag(0, 1)
#define bktlist_flag_lookup_tail bktlist_lookup_flag(0, 0)
#define bktlist_flag_ins_front bktlist_lookup_flag(1, 1)
#define bktlist_flag_ins_tail bktlist_lookup_flag(1, 0)
#define bktlist_flag_delete_front bktlist_delete_flag(1)
#define bktlist_flag_delete_tail bktlist_delete_flag(0)

extern __u64 bpf_ffs(__u64 val) __ksym;

#undef __ffs
#define __ffs bpf_ffs

struct __packet_type {
	__u64 data;
};

DECLARE_SIMPLE_RINGBUF(pkt_bkt, struct __packet_type, PKT_BKT_SIZE_SHIFT)
DECLARE_HPIQ(cffs, 2, bitmap_type)

struct cffs_piq {
	struct hpiq__cffs hpiq[2];
	bool prime;
	__u32 h_index;
};

struct node_data {
	struct __packet_type data;
	struct bpf_list_node node;
};

struct bucket_list {
	struct bpf_list_head head __contains(node_data, node);
	struct bpf_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct bucket_list);
	__uint(max_entries, 2 * BUCKET_NUM * CPU_CORES);
} bucket_list_percpu_map SEC(".maps");

static __always_inline int bucket_list_push_back(struct bpf_list_head *head,
						 struct bpf_spin_lock *lock,
						 struct __packet_type *value)
{
	struct node_data *n;
	struct bpf_list_node *rn;
	int res;
	n = bpf_obj_new(typeof(*n));
	if (!n)
		return -1;
	__builtin_memcpy(&n->data, value, sizeof(struct __packet_type));

	bpf_spin_lock(lock);
	res = bpf_list_push_back(head, &n->node);
	bpf_spin_unlock(lock);

	if (res != 0) {
		log_error("res: %d", res);
		return -1;
	}
	return 0;
}

static __always_inline int bucket_list_pop_front(struct bpf_list_head *head,
						 struct bpf_spin_lock *lock,
						 struct __packet_type *value)
{
	struct bpf_list_node *rn;
	int res;
	bpf_spin_lock(lock);
	rn = bpf_list_pop_front(head);
	bpf_spin_unlock(lock);
	if (!rn)
		return -1;
	struct node_data *res_node = container_of(rn, struct node_data, node);
	__builtin_memcpy(value, &res_node->data, sizeof(struct __packet_type));
	bpf_obj_drop(res_node);
	return 0;
}

static __inline int cffs_enqueue(struct cffs_piq *cffs,
				 void *__bucket_list_percpu_map, __u32 prio,
				 const struct __packet_type *pkt, __u32 cpu)
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
	// add the cpu number to determine the percpu bucket_list
	int key = (idx * BUCKET_NUM + __bktnum) + (2 * BUCKET_NUM * cpu);

	log_debug("bktnum : %u", bktnum);
	log_debug("__bucket_num: %u", __bktnum);
	log_debug("hindex: %u", cffs->h_index);
	log_debug("use prime :%d, current prime: %d, cal idx :%d", use_prime,
		  cffs->prime, idx);
	log_debug("percpu bkt key: %d", key);

	struct bucket_list *bucket_list;
	bucket_list = bpf_map_lookup_elem(__bucket_list_percpu_map, &key);
	if (bucket_list == NULL)
		return -1;
	//insert the packet to bucket ringbuf
	int push_res = bucket_list_push_back(&bucket_list->head,
					     &bucket_list->lock, pkt);
	if (push_res != 0)
		return -2; //ring buffer is full
	asm_bound_check(idx, 2); //to make the verifier happy
	hpiq_insert__cffs(&cffs->hpiq[idx], __bktnum);
	log_debug("cffs_enqueue: prime hpiq first level: %x",
		  cffs->hpiq[idx].bitmap_lvl_1);
	return 0;
}

static __inline struct bucket_list *
cffs_first_bkt(struct cffs_piq *cffs, void *__bucket_list_percpu_map,
	       __u32 *bktnum, __u32 cpu)
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
	int key = (int)cffs->prime * BUCKET_NUM + (int)(__bktnum) + (2 * BUCKET_NUM * cpu);
	*bktnum = __bktnum;
	return bpf_map_lookup_elem(__bucket_list_percpu_map, &key);
}

// get the specific bucket_list from cffs_first_bkt() and dequeue the first packet from the bucket_list
static __inline void cffs_dequeue(struct cffs_piq *cffs,
				  struct bucket_list *__bucket_list,
				  __u32 bktnum, struct __packet_type *res)
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
	bucket_list_pop_front(&__bucket_list->head, &__bucket_list->lock,
			      res);
}

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct cffs_piq);
	__uint(max_entries, 1);
} cffs_piq_map SEC(".maps");


SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	int key = 0, res;
	struct cffs_piq *cffs;
	struct bucket_list *__bucket_list;
	__u32 cpu = bpf_get_smp_processor_id();
	cffs = bpf_map_lookup_elem(&cffs_piq_map, &key);
	if (cffs == NULL) {
		goto xdp_error;
	}
	//enquene
	__u32 prio = 10;
	struct __packet_type pkt = { .data = (__u64)prio };
	res = cffs_enqueue(cffs, (void *)&bucket_list_percpu_map, prio, &pkt, cpu);

	//dequeue
	__u32 bktnum = 0;
	__bucket_list =
		cffs_first_bkt(cffs, (void *)&bucket_list_percpu_map, &bktnum, cpu);
	if (__bucket_list == NULL) {
		goto xdp_error;
	}

	struct __packet_type __pkt;
	cffs_dequeue(cffs, __bucket_list, bktnum, &__pkt);
	log_debug("dequeue pkt: %u", __pkt.data);
	return XDP_DROP;
xdp_error:
	log_error("xdp_error");
	return XDP_DROP;
}
