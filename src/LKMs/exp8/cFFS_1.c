#include <linux/init.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/bpf.h>
#include <linux/bitops.h>
#include "./simple_ringbuf.h"

extern int bpf_register_static_cmap(struct bpf_map_ops *map,
				    struct module *onwer);
extern void bpf_unregister_static_cmap(struct module *onwer);
extern void bpf_map_area_free(void *area);
extern void *bpf_map_area_alloc(u64 size, int numa_node);

typedef __u32 bitmap_type;
#define PER_LONG_BITS_SHIFT 5 //64 per long

#ifndef PKT_BKT_SIZE_SHIFT
#define PKT_BKT_SIZE_SHIFT 8
#endif

#ifndef PKT_BKT_SIZE
#define PKT_BKT_SIZE SHIFT_TO_SIZE(PKT_BKT_SIZE_SHIFT)
#endif

struct __packet_type {
	__u64 data;
};

#define HBITMAP_LEVEL_1_SHIFT (PER_LONG_BITS_SHIFT)
#define HBITMAP_LEVEL_1 SHIFT_TO_SIZE(HBITMAP_LEVEL_1_SHIFT)

#define HBITMAP_LEVEL_2_SHIFT (PER_LONG_BITS_SHIFT + PER_LONG_BITS_SHIFT)
#define HBITMAP_LEVEL_2 SHIFT_TO_SIZE(HBITMAP_LEVEL_2_SHIFT)

#define HBITMAP_LEVEL_3_SHIFT \
	(PER_LONG_BITS_SHIFT + PER_LONG_BITS_SHIFT + PER_LONG_BITS_SHIFT)
#define HBITMAP_LEVEL_3 SHIFT_TO_SIZE(HBITMAP_LEVEL_3_SHIFT)

#define HBITMAP_LEVEL_4_SHIFT                                              \
	(PER_LONG_BITS_SHIFT + PER_LONG_BITS_SHIFT + PER_LONG_BITS_SHIFT + \
	 PER_LONG_BITS_SHIFT)
#define HBITMAP_LEVEL_4 SHIFT_TO_SIZE(HBITMAP_LEVEL_4_SHIFT)

#define HBITMAP_LEVEL(n) HBITMAP_LEVEL_##n

#define BUCKET_NUM HBITMAP_LEVEL_2
#define BUCKET_NUM_SHIFT HBITMAP_LEVEL_2_SHIFT

/* Hierarchical priority index queue*/
#define DECLARE_HIE_PRIO_IDX_QUEUE_LVL_1(__bitmap_type) \
	__bitmap_type bitmap_lvl_1;

#define DECLARE_HIE_PRIO_IDX_QUEUE_LVL_2(__bitmap_type) \
	DECLARE_HIE_PRIO_IDX_QUEUE_LVL_1(__bitmap_type) \
	__bitmap_type bitmap_lvl_2[HBITMAP_LEVEL_1];

#define DECLARE_HIE_PRIO_IDX_QUEUE_LVL_3(__bitmap_type) \
	DECLARE_HIE_PRIO_IDX_QUEUE_LVL_2(__bitmap_type) \
	__bitmap_type bitmap_lvl_3[HBITMAP_LEVEL_2];

#define DECLARE_HIE_PRIO_IDX_QUEUE_LVL_4(__bitmap_type) \
	DECLARE_HIE_PRIO_IDX_QUEUE_LVL_3(__bitmap_type) \
	__bitmap_type bitmap_lvl_4[HBITMAP_LEVEL_3];

#define DECLARE_HIE_PRIO_IDX_QUEUE_LVL(n, __bitmap_type) \
	DECLARE_HIE_PRIO_IDX_QUEUE_LVL_##n(__bitmap_type)

#define hpiq_cal_idx_lvl_1(_name, __bitmap_type) \
	__bitmap_type __idx1 = __ffs(hpiq->bitmap_lvl_1);

#define hpiq_cal_idx_lvl_2(_name, __bitmap_type) \
	hpiq_cal_idx_lvl_1(_name, __bitmap_type) \
		__bitmap_type __idx2 = __ffs(hpiq->bitmap_lvl_2[__idx1]);

#define hpiq_cal_idx_lvl_3(_name, __bitmap_type) \
	hpiq_cal_idx_lvl_2(_name, __bitmap_type) \
		__bitmap_type __idx3 = __ffs(hpiq->bitmap_lvl_3[__idx2]);

#define hpiq_cal_idx_lvl(n, _name, __bitmap_type) \
	hpiq_cal_idx_lvl_##n(_name, __bitmap_type)

#define hpiq_front_idx_lvl_1(_name, __bitmap_type)                          \
	static __always_inline __bitmap_type hpiq_front_idx_lvl_1__##_name( \
		struct hpiq__##_name *hpiq)                                 \
	{                                                                   \
		return __ffs(hpiq->bitmap_lvl_1);                           \
	}

#define hpiq_front_idx_lvl_2(_name, __bitmap_type)                          \
	static __always_inline __bitmap_type hpiq_front_idx_lvl_2__##_name( \
		struct hpiq__##_name *hpiq)                                 \
	{                                                                   \
		hpiq_cal_idx_lvl(1, _name, __bitmap_type) return (          \
			__idx1 << HBITMAP_LEVEL_1_SHIFT) +                  \
			__ffs(hpiq->bitmap_lvl_2[__idx1]);                  \
	}

#define hpiq_front_idx_lvl_3(_name, __bitmap_type)                          \
	static __always_inline __bitmap_type hpiq_front_idx_lvl_3__##_name( \
		struct hpiq__##_name *hpiq)                                 \
	{                                                                   \
		hpiq_cal_idx_lvl(2, _name, __bitmap_type) return (          \
			__idx1 << HBITMAP_LEVEL_2_SHIFT) +                  \
			(__idx2 << HBITMAP_LEVEL_1_SHIFT) +                 \
			__ffs(hpiq->bitmap_lvl_3[__idx2]);                  \
	}

#define hpiq_front_idx_lvl_4(_name, __bitmap_type)                          \
	static __always_inline __bitmap_type hpiq_front_idx_lvl_4__##_name( \
		struct hpiq__##_name *hpiq)                                 \
	{                                                                   \
		hpiq_cal_idx_lvl(3, _name, __bitmap_type) return (          \
			__idx1 << HBITMAP_LEVEL_3_SHIFT) +                  \
			(__idx2 << HBITMAP_LEVEL_2_SHIFT) +                 \
			(__idx3 << HBITMAP_LEVEL_1_SHIFT) +                 \
			__ffs(hpiq->bitmap_lvl_4[__idx3]);                  \
	}
#define hpiq_front_idx_lvl(level, _name, __bitmap_type) \
	hpiq_front_idx_lvl_##level(_name, __bitmap_type)

#define hpiq_get_idx_offset_lvl_1(__bitmap_type, bucket) \
	__bitmap_type __tmp = (__bitmap_type)(bucket);   \
	__bitmap_type __off1 = BOUND_INDEX(__tmp, PER_LONG_BITS_SHIFT);

#define hpiq_get_idx_offset_lvl_2(__bitmap_type, bucket) \
	hpiq_get_idx_offset_lvl_1(__bitmap_type, bucket) \
		__tmp = (__tmp >> PER_LONG_BITS_SHIFT);  \
	__bitmap_type __off2 = BOUND_INDEX(__tmp, PER_LONG_BITS_SHIFT);

#define hpiq_get_idx_offset_lvl_3(__bitmap_type, bucket) \
	hpiq_get_idx_offset_lvl_2(__bitmap_type, bucket) \
		__tmp = (__tmp >> PER_LONG_BITS_SHIFT);  \
	__bitmap_type __off3 = BOUND_INDEX(__tmp, PER_LONG_BITS_SHIFT);

#define hpiq_get_idx_offset_lvl_4(__bitmap_type, bucket) \
	hpiq_get_idx_offset_lvl_3(__bitmap_type, bucket) \
		__tmp = (__tmp >> PER_LONG_BITS_SHIFT);  \
	__bitmap_type __off4 = BOUND_INDEX(__tmp, PER_LONG_BITS_SHIFT);

#define hpiq_get_idx_offset_lvl(level, __bitmap_type, bucke) \
	hpiq_get_idx_offset_lvl_##level(__bitmap_type, bucket)

#define hpiq_insert_lvl_1(_name, __bitmap_type)                             \
	static __always_inline void hpiq_insert_lvl_1__##_name(             \
		struct hpiq__##_name *hpiq, __u32 bucket)                   \
	{                                                                   \
		hpiq_get_idx_offset_lvl(1, __bitmap_type, bucket)           \
			hpiq->bitmap_lvl_1 |= ((__bitmap_type)1 << __off1); \
	}

#define hpiq_insert_lvl_2(_name, __bitmap_type)                             \
	static __always_inline void hpiq_insert_lvl_2__##_name(             \
		struct hpiq__##_name *hpiq, __u32 bucket)                   \
	{                                                                   \
		hpiq_get_idx_offset_lvl(2, __bitmap_type, bucket)           \
			hpiq->bitmap_lvl_1 |=                               \
			(__bitmap_type)((__bitmap_type)1 << __off2);        \
		hpiq->bitmap_lvl_2[__off2] |= ((__bitmap_type)1 << __off1); \
	}

#define hpiq_insert_lvl_3(_name, __bitmap_type)                             \
	static __always_inline void hpiq_insert_lvl_3__##_name(             \
		struct hpiq__##_name *hpiq, __u32 bucket)                   \
	{                                                                   \
		hpiq_get_idx_offset_lvl(3, __bitmap_type, bucket)           \
			hpiq->bitmap_lvl_1 |= ((__bitmap_type)1 << __off3); \
		hpiq->bitmap_lvl_2[__off3] |= ((__bitmap_type)1 << __off2); \
		hpiq->bitmap_lvl_3[__off2] |= ((__bitmap_type)1 << __off1); \
	}

#define hpiq_insert_lvl_4(_name, __bitmap_type)                             \
	static __always_inline void hpiq_insert_lvl_4__##_name(             \
		struct hpiq__##_name *hpiq, __u32 bucket)                   \
	{                                                                   \
		hpiq_get_idx_offset_lvl(4, __bitmap_type, bucket)           \
			hpiq->bitmap_lvl_1 |= ((__bitmap_type)1 << __off4); \
		hpiq->bitmap_lvl_2[__off4] |= ((__bitmap_type)1 << __off3); \
		hpiq->bitmap_lvl_3[__off3] |= ((__bitmap_type)1 << __off2); \
		hpiq->bitmap_lvl_4[__off2] |= ((__bitmap_type)1 << __off1); \
	}

#define hpiq_insert_lvl(level, _name, __bitmap_type) \
	hpiq_insert_lvl_##level(_name, __bitmap_type)

#define hpiq_delete_lvl_1(_name, __bitmap_type)                              \
	static __always_inline void hpiq_delete_lvl_1__##_name(              \
		struct hpiq__##_name *hpiq, __u32 bucket)                    \
	{                                                                    \
		hpiq_get_idx_offset_lvl(1, __bitmap_type, bucket)            \
			hpiq->bitmap_lvl_1 &= ~((__bitmap_type)1 << __off1); \
	}

#define hpiq_delete_lvl_2(_name, __bitmap_type)                              \
	static __always_inline void hpiq_delete_lvl_2__##_name(              \
		struct hpiq__##_name *hpiq, __u32 bucket)                    \
	{                                                                    \
		hpiq_get_idx_offset_lvl(2, __bitmap_type, bucket)            \
			hpiq->bitmap_lvl_2[__off2] &=                        \
			~((__bitmap_type)1 << __off1);                       \
		if (hpiq->bitmap_lvl_2[__off2] == 0)                         \
			hpiq->bitmap_lvl_1 &= ~((__bitmap_type)1 << __off2); \
	}

#define hpiq_delete_lvl_3(_name, __bitmap_type)                              \
	static __always_inline void hpiq_delete_lvl_3__##_name(              \
		struct hpiq__##_name *hpiq, __u32 bucket)                    \
	{                                                                    \
		hpiq_get_idx_offset_lvl(3, __bitmap_type, bucket)            \
			hpiq->bitmap_lvl_3[__off2] &=                        \
			~((__bitmap_type)1 << __off1);                       \
		if (hpiq->bitmap_lvl_3[__off2] == 0)                         \
			hpiq->bitmap_lvl_2[__off3] &=                        \
				~((__bitmap_type)1 << __off2);               \
		if (hpiq->bitmap_lvl_2[__off3] == 0)                         \
			hpiq->bitmap_lvl_1 &= ~((__bitmap_type)1 << __off3); \
	}

#define hpiq_delete_lvl_4(_name, __bitmap_type)                              \
	static __always_inline void hpiq_delete_lvl_4__##_name(              \
		struct hpiq__##_name *hpiq, __u32 bucket)                    \
	{                                                                    \
		hpiq_get_idx_offset_lvl(4, __bitmap_type, bucket)            \
			hpiq->bitmap_lvl_4[__off2] &=                        \
			~((__bitmap_type)1 << __off1);                       \
		if (hpiq->bitmap_lvl_4[__off2] == 0)                         \
			hpiq->bitmap_lvl_3[__off3] &=                        \
				~((__bitmap_type)1 << __off2);               \
		if (hpiq->bitmap_lvl_3[__off3] == 0)                         \
			hpiq->bitmap_lvl_2[__off4] &=                        \
				~((__bitmap_type)1 << __off3);               \
		if (hpiq->bitmap_lvl_2[__off4] == 0)                         \
			hpiq->bitmap_lvl_1 &= ~((__bitmap_type)1 << __off4); \
	}

#define hpiq_delete_lvl(level, _name, __bitmap_type) \
	hpiq_delete_lvl_##level(_name, __bitmap_type)

//x1 * HBITMAP_LEVEL(n-1) +  x2 * HBITMAP_LEVEL(n-2) + ....  xn
/* should define PER_LONG_BITS_SHIFT for ffs*/
#define DECLARE_HPIQ(_name, level, __bitmap_type)                              \
	struct hpiq__##_name {                                                 \
		DECLARE_HIE_PRIO_IDX_QUEUE_LVL(level, __bitmap_type)           \
	};                                                                     \
	hpiq_front_idx_lvl(level, _name,                                       \
			   __bitmap_type) static __always_inline __bitmap_type \
		hpiq_front_idx__##_name(struct hpiq__##_name *hpiq)            \
	{                                                                      \
		return hpiq_front_idx_lvl_##level##__##_name(hpiq);            \
	}                                                                      \
	hpiq_insert_lvl(level, _name,                                          \
			__bitmap_type) static __always_inline void             \
		hpiq_insert__##_name(struct hpiq__##_name *hpiq, __u32 bucket) \
	{                                                                      \
		return hpiq_insert_lvl_##level##__##_name(hpiq, bucket);       \
	}                                                                      \
	hpiq_delete_lvl(level, _name,                                          \
			__bitmap_type) static __always_inline void             \
		hpiq_delete__##_name(struct hpiq__##_name *hpiq, __u32 bucket) \
	{                                                                      \
		return hpiq_delete_lvl_##level##__##_name(hpiq, bucket);       \
	}

DECLARE_SIMPLE_RINGBUF(pkt_bkt, struct __packet_type, PKT_BKT_SIZE_SHIFT)
DECLARE_HPIQ(cffs, 1, bitmap_type)

/*current use percpu to perform concurrent control*/

struct cffs_piq {
	struct hpiq__cffs hpiq[2] ____cacheline_aligned;
	bool prime;
	__u32 h_index;
};

struct cffs_piq_map {
	struct bpf_map map;
	struct cffs_piq __percpu *cffs;
	struct simple_rbuf__pkt_bkt __percpu *bkts[2 * BUCKET_NUM];
};

struct __cffs_key_type {
	u32 prio;
};

struct __cffs_value_type {
	struct __packet_type pkt;
};

// extern int bpf_register_custom_map(struct bpf_custom_map_ops *cmap);
// extern void bpf_unregister_custom_map(struct bpf_custom_map_ops *cmap);

int cffs_piq_alloc_check(union bpf_attr *attr)
{
	if (attr->key_size != sizeof(struct __cffs_key_type) ||
	    attr->value_size != sizeof(struct __cffs_value_type) ||
	    attr->max_entries != BUCKET_NUM) {
		return -EINVAL;
	}
	return 0;
}

static void cffs_free_bkts(struct cffs_piq_map *cmap)
{
	int i;
	for (i = 0; i < 2 * BUCKET_NUM; i++) {
		free_percpu(cmap->bkts[i]);
	}
	return;
}

/*
*@return 0 means success
*/
static int cffs_alloc_bkts(struct cffs_piq_map *cmap)
{
	int i;
	for (i = 0; i < 2 * BUCKET_NUM; i++) {
		struct simple_rbuf__pkt_bkt __percpu *bkt;
		bkt = __alloc_percpu_gfp(sizeof(struct simple_rbuf__pkt_bkt),
					 __alignof__(u64),
					 GFP_USER | __GFP_NOWARN);
		if (bkt == NULL) {
			goto err_free;
		}
		cmap->bkts[i] = bkt;
	}
	return 0;
err_free:;
	cffs_free_bkts(cmap);
	return -ENOMEM;
}

static struct bpf_map *cffs_piq_alloc(union bpf_attr *attr)
{
	//demo alloc we just alloc char[hello world]
	struct cffs_piq_map *cmap;
	void *res_ptr;
	int cpu, i;
	cmap = bpf_map_area_alloc(sizeof(*cmap), NUMA_NO_NODE);
	if (cmap == NULL) {
		return ERR_PTR(-ENOMEM);
	}
	memset(&cmap->map, 0, sizeof(cmap->map));
	cmap->cffs = __alloc_percpu_gfp(sizeof(struct cffs_piq),
					__alignof__(u64),
					GFP_USER | __GFP_NOWARN);
	if (cmap->cffs == NULL) {
		res_ptr = ERR_PTR(-ENOMEM);
		goto free_cmap;
	}
	for_each_possible_cpu(cpu) {
		memset(per_cpu_ptr(cmap->cffs, cpu), 0,
		       sizeof(struct cffs_piq));
	}

	if (cffs_alloc_bkts(cmap)) {
		res_ptr = ERR_PTR(-ENOMEM);
		goto free_cffs;
	}
	for_each_possible_cpu(cpu) {
		for (i = 0; i < 2 * BUCKET_NUM; i++) {
			memset(per_cpu_ptr(cmap->bkts[i], cpu), 0,
			       sizeof(struct simple_rbuf__pkt_bkt));
		}
	}
	return (struct bpf_map *)cmap;

free_cffs:;
	free_percpu(cmap->cffs);

free_cmap:;
	bpf_map_area_free(cmap);
	return (struct bpf_map *)res_ptr;
}

static void cffs_piq_free(struct bpf_map *map)
{
	struct cffs_piq_map *cmap = (struct cffs_piq_map *)map;
	cffs_free_bkts(cmap);
	free_percpu(cmap->cffs);
	bpf_map_area_free(cmap);
}

/*enqueue elem*/
static long cffs_piq_update_elem(struct bpf_map *map, void *key, void *value,
				 u64 flags)
{
	struct cffs_piq_map *cmap = container_of(map, struct cffs_piq_map, map);
	struct __cffs_key_type *__key = (struct __cffs_key_type *)key;
	struct __cffs_value_type *__value = (struct __cffs_value_type *)value;
	struct cffs_piq *cffs;
	struct __packet_type *prod;
	struct simple_rbuf__pkt_bkt *pktbuf;
	u32 bktnum, __bktnum, prio, __bkt_idx;
	bool use_prime, idx;

	cffs = this_cpu_ptr(cmap->cffs);
	bktnum = prio = __key->prio;

	if (unlikely(prio >= (cffs->h_index + 2 * BUCKET_NUM))) {
		bktnum = cffs->h_index + 2 * BUCKET_NUM - 1;
	} else if (unlikely(prio < cffs->h_index)) {
		bktnum = cffs->h_index;
	}

	bktnum -=
		cffs->h_index; //bounded to [0, 2 * BUCKET_NUM], real prio is h_index + prio

	//prime:True used_prime:True => True, prime:True, use_prime:False => False. prime:False, use_prime:True => False, prime: False, use_prime:False => True
	use_prime = (bktnum < BUCKET_NUM);
	idx = !(use_prime ^ cffs->prime); //use prime or secondary hffs
	__bktnum = bktnum - (!(use_prime)) * BUCKET_NUM;
	__bkt_idx = idx * BUCKET_NUM + __bktnum;

	pr_debug("prio :%u", prio);
	pr_debug("bktnum : %u", bktnum);
	pr_debug("__bucket_num: %u", __bktnum);
	pr_debug("hindex: %u", cffs->h_index);
	pr_debug("use prime :%d, current prime: %d, cal idx :%d", use_prime,
		 cffs->prime, idx);
	pr_debug("percpu bkt key: %u", __bkt_idx);

	pktbuf = this_cpu_ptr(cmap->bkts[__bkt_idx]);

	//insert the packet to bucket ringbuf
	prod = pkt_bkt__simple_rbuf_prod(pktbuf);
	if (prod == NULL) {
		//ring buffer is full
		return -2;
	}

	hpiq_insert__cffs(&cffs->hpiq[idx], __bktnum);
	pr_debug("cffs_enqueue: prime hpiq first level: %llx",
		 cffs->hpiq[idx].bitmap_lvl_1);

	memcpy(prod, __value, sizeof(*prod));
	pkt_bkt__simple_rbuf_submit(pktbuf);
	return 0;
}

static long cffs_piq_pop_elem(struct bpf_map *map, void *value)
{
	struct cffs_piq_map *cmap = container_of(map, struct cffs_piq_map, map);
	struct cffs_piq *cffs;
	struct hpiq__cffs *phpiq;
	struct simple_rbuf__pkt_bkt *pktbuf;
	struct __packet_type *__pkt;
	u32 __bktnum, bkt_idx;
	cffs = this_cpu_ptr(cmap->cffs);

	phpiq = &cffs->hpiq[cffs->prime];
	if (unlikely(phpiq->bitmap_lvl_1) == 0) {
		struct hpiq__cffs *snd_hpiq = &cffs->hpiq[!cffs->prime];
		if (snd_hpiq->bitmap_lvl_1 == 0) {
			//non packet
			pr_debug("cffs is empty");
			return -1;
		} else {
			//switch the primary
			pr_debug("cffs_first_bkt: switch primary");
			cffs->prime = !(cffs->prime);
			cffs->h_index += BUCKET_NUM;
			phpiq = snd_hpiq;
		}
	}
	pr_debug("cffs_first_bkt: current prime: %d", cffs->prime);
	__bktnum = (__u32)hpiq_front_idx__cffs(phpiq);
	pr_debug("cffs_first_bkt: front bkt %u", __bktnum);

	bkt_idx = (u32)cffs->prime * BUCKET_NUM + (int)(__bktnum);

	pktbuf = this_cpu_ptr(cmap->bkts[bkt_idx]);
	__pkt = pkt_bkt__simple_rbuf_cons(pktbuf);
	memcpy(value, __pkt, sizeof(struct __cffs_value_type)); /*copy to ebpf*/
	pkt_bkt__simple_rbuf_release(pktbuf);

	hpiq_delete__cffs(phpiq, __bktnum);
	if (unlikely(phpiq->bitmap_lvl_1 == 0)) {
		//switch prime
		if (cffs->hpiq[!cffs->prime].bitmap_lvl_1 != 0) {
			cffs->prime = !(cffs->prime);
			cffs->h_index += BUCKET_NUM;
		}
	}
	return 0;
}

static u64 cffs_piq_mem_usage(const struct bpf_map *map)
{
	u64 used = 0;
	used += sizeof(struct cffs_piq) * num_possible_cpus();
	used += sizeof(struct simple_rbuf__pkt_bkt) * (2 * BUCKET_NUM) *
		num_possible_cpus();
	return used;
}

static struct bpf_map_ops cffs_piq_ops = {
	.map_alloc_check = cffs_piq_alloc_check,
	.map_alloc = cffs_piq_alloc,
	.map_free = cffs_piq_free,
	.map_update_elem = cffs_piq_update_elem,
	.map_pop_elem = cffs_piq_pop_elem,
	.map_mem_usage = cffs_piq_mem_usage
};

//extern int bpf_register_static_cmap(struct bpf_map_ops *map, struct module *onwer);
//extern void bpf_unregister_static_cmap(struct module *onwer);

static int __init static_cffs_piq_init(void)
{
	pr_info("register static cffs_piq");
	return bpf_register_static_cmap(&cffs_piq_ops, THIS_MODULE);
}

static void __exit static_cffs_piq_exit(void)
{
	pr_info("unregister static cffs_piq");
	bpf_unregister_static_cmap(THIS_MODULE);
}

/* Register module functions */
module_init(static_cffs_piq_init);
module_exit(static_cffs_piq_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chonepieceyb");
MODULE_DESCRIPTION("cffs LKM implementation");
MODULE_VERSION("0.01");