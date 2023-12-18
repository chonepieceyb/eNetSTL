#include "common.h"
#include "vmlinux.h"

char _license[] SEC("license") = "GPL";

/***********************************************
*********************PKTBKT PERCPU**************
************************************************/

typedef __u32 bitmap_type;
#define PER_LONG_BITS_SHIFT 5  //64 per long
#define __ffs __ffs32
#define BITS_PER_LONG sizeof(bitmap_type)

#ifndef PKT_BKT_SIZE_SHIFT 
#define PKT_BKT_SIZE_SHIFT 8
#endif 

#ifndef PKT_BKT_SIZE 
#define PKT_BKT_SIZE SHIFT_TO_SIZE(PKT_BKT_SIZE_SHIFT)
#endif                                                           

struct __packet_type {
        __u64 data; 
};

#define HBITMAP_LEVEL_1 SHIFT_TO_SIZE(PER_LONG_BITS_SHIFT)
#define HBITMAP_LEVEL_2 SHIFT_TO_SIZE(PER_LONG_BITS_SHIFT + PER_LONG_BITS_SHIFT)
#define HBITMAP_LEVEL_3 SHIFT_TO_SIZE(PER_LONG_BITS_SHIFT + PER_LONG_BITS_SHIFT + PER_LONG_BITS_SHIFT)
#define HBITMAP_LEVEL_4 SHIFT_TO_SIZE(PER_LONG_BITS_SHIFT + PER_LONG_BITS_SHIFT + PER_LONG_BITS_SHIFT + PER_LONG_BITS_SHIFT)

#define HBITMAP_LEVEL(n) HBITMAP_LEVEL_##n

DECLARE_SIMPLE_RINGBUF(pkt_bkt, struct __packet_type, PKT_BKT_SIZE_SHIFT)

/* Hierarchical priority index queue*/
#define DECLARE_HIE_PRIO_IDX_QUEUE_LVL_1(__bitmap_type)               \
        __bitmap_type bitmap_lvl_1;

#define DECLARE_HIE_PRIO_IDX_QUEUE_LVL_2(__bitmap_type)               \
        DECLARE_HIE_PRIO_IDX_QUEUE_LVL_1(__bitmap_type)                 \
        __bitmap_type bitmap_lvl_2[HBITMAP_LEVEL_1];

#define DECLARE_HIE_PRIO_IDX_QUEUE_LVL_3(__bitmap_type)               \
        DECLARE_HIE_PRIO_IDX_QUEUE_LVL_2(__bitmap_type)                 \
        __bitmap_type bitmap_lvl_3[HBITMAP_LEVEL_2];

#define DECLARE_HIE_PRIO_IDX_QUEUE_LVL_4(__bitmap_type)               \
        DECLARE_HIE_PRIO_IDX_QUEUE_LVL_3(__bitmap_type)                 \
        __bitmap_type bitmap_lvl_4[HBITMAP_LEVEL_3];


#define  DECLARE_HIE_PRIO_IDX_QUEUE_LVL(n, __bitmap_type) DECLARE_HIE_PRIO_IDX_QUEUE_LVL_##n(__bitmap_type)

#define hpiq_cal_idx_lvl_1(_name, __bitmap_type)                \
        __bitmap_type __idx1 = BOUND_INDEX(__ffs(hpiq->bitmap_lvl_1), PER_LONG_BITS_SHIFT);

#define hpiq_cal_idx_lvl_2(_name, __bitmap_type)                \
        hpiq_cal_idx_lvl_1(_name, __bitmap_type)              \
        __bitmap_type __idx2 = BOUND_INDEX(__ffs(hpiq->bitmap_lvl_2[__idx1]), PER_LONG_BITS_SHIFT);

#define hpiq_cal_idx_lvl_3(_name, __bitmap_type)                \
        hpiq_cal_idx_lvl_2(_name, __bitmap_type)              \
        __bitmap_type __idx3 = BOUND_INDEX(__ffs(hpiq->bitmap_lvl_3[__idx2]), PER_LONG_BITS_SHIFT);

#define hpiq_cal_idx_lvl(n, _name, __bitmap_type) hpiq_cal_idx_lvl_##n(_name, __bitmap_type)

#define hpiq_front_idx_lvl_1(_name, __bitmap_type)                                              \
static __always_inline __bitmap_type hpiq_front_idx_lvl_1__##_name(struct hpiq__##_name *hpiq)    \
{                                                                                                   \
        return __ffs(hpiq->bitmap_lvl_1);                                               \
}    

#define hpiq_front_idx_lvl_2(_name, __bitmap_type)                                              \
static __always_inline __bitmap_type hpiq_front_idx_lvl_2__##_name(struct hpiq__##_name *hpiq)    \
{                                                                               \
        hpiq_cal_idx_lvl(1, _name, __bitmap_type)                                   \
        return  __idx1 * HBITMAP_LEVEL_1 + __ffs(hpiq->bitmap_lvl_2[__idx1]);                               \
}  

#define hpiq_front_idx_lvl_3(_name, __bitmap_type)                                              \
static __always_inline __bitmap_type hpiq_front_idx_lvl_3__##_name(struct hpiq__##_name *hpiq)    \
{                                                                                                   \
        hpiq_cal_idx_lvl(2, _name, __bitmap_type)                          \
        return  __idx1 * HBITMAP_LEVEL_2 + __idx2 * HBITMAP_LEVEL_1  +  __ffs(hpiq->bitmap_lvl_3[__idx2]);        \
}   

#define hpiq_front_idx_lvl_4(_name, __bitmap_type)                                              \
static __always_inline __bitmap_type hpiq_front_idx_lvl_4__##_name(struct hpiq__##_name *hpiq)    \
{                                                                                                   \
        hpiq_cal_idx_lvl(3, _name, __bitmap_type)                                               \
        return  __idx1 * HBITMAP_LEVEL_3 + __idx2 * HBITMAP_LEVEL_2 + __idx3 * HBITMAP_LEVEL_1 + __ffs(hpiq->bitmap_lvl_4[__idx3]);        \
} 
#define hpiq_front_idx_lvl(level, _name, __bitmap_type) hpiq_front_idx_lvl_##level(_name, __bitmap_type)

#define hpiq_get_idx_offset_lvl_1(__bitmap_type, bucket)                           \
        __bitmap_type __tmp = (bucket);                                           \
        __bitmap_type __off1 =  BOUND_INDEX(__tmp, PER_LONG_BITS_SHIFT);          

#define hpiq_get_idx_offset_lvl_2(__bitmap_type, bucket)      \
        hpiq_get_idx_offset_lvl_1(__bitmap_type, bucket)                          \
        __tmp = (__tmp >> PER_LONG_BITS_SHIFT);                                             \
        __bitmap_type __off2 =  BOUND_INDEX(__tmp, PER_LONG_BITS_SHIFT);

#define hpiq_get_idx_offset_lvl_3( __bitmap_type, bucket)      \
        hpiq_get_idx_offset_lvl_2(__bitmap_type, bucket)                          \
        __tmp = (__tmp >> PER_LONG_BITS_SHIFT);                                             \
        __bitmap_type __off3 =  BOUND_INDEX(__tmp, PER_LONG_BITS_SHIFT);

#define hpiq_get_idx_offset_lvl_4(__bitmap_type, bucket)      \
        hpiq_get_idx_offset_lvl_3(__bitmap_type, bucket)                          \
        __tmp = (___tmp >> PER_LONG_BITS_SHIFT);                                             \
        __bitmap_type __off4 =  BOUND_INDEX(__tmp, PER_LONG_BITS_SHIFT);

#define hpiq_get_idx_offset_lvl(level, __bitmap_type, bucke) hpiq_get_idx_offset_lvl_##level(__bitmap_type, bucket)

#define hpiq_insert_lvl_1(_name, __bitmap_type)                                              \
static __always_inline void hpiq_insert_lvl_1__##_name(struct hpiq__##_name *hpiq, __u32 bucket)    \
{                                                                                                   \
        hpiq_get_idx_offset_lvl(1, __bitmap_type, bucket)                                                       \
        hpiq->bitmap_lvl_1 |= (__bitmap_type)(1 << __off1);                            \
}    

#define hpiq_insert_lvl_2(_name, __bitmap_type)                                              \
static __always_inline void hpiq_insert_lvl_2__##_name(struct hpiq__##_name *hpiq, __u32 bucket)    \
{                                                                                                   \
        hpiq_get_idx_offset_lvl(2, __bitmap_type, bucket)                                                       \
        hpiq->bitmap_lvl_1 |= (__bitmap_type)(1 << __off2);                            \
        hpiq->bitmap_lvl_2[__off2] |= (__bitmap_type)(1 << __off1);                            \
}    

#define hpiq_insert_lvl_3(_name, __bitmap_type)                                              \
static __always_inline void hpiq_insert_lvl_3__##_name(struct hpiq__##_name *hpiq, __u32 bucket)    \
{                                                                                                   \
        hpiq_get_idx_offset_lvl(3, __bitmap_type, bucket)                                                       \
        hpiq->bitmap_lvl_1 |= (__bitmap_type)(1 << __off3);                            \
        hpiq->bitmap_lvl_2[__off3] |= (__bitmap_type)(1 << __off2);                            \
        hpiq->bitmap_lvl_3[__off2] |= (__bitmap_type)(1 << __off1);                            \
}    

#define hpiq_insert_lvl_4(_name, __bitmap_type)                                              \
static __always_inline void hpiq_insert_lvl_4__##_name(struct hpiq__##_name *hpiq, __u32 bucket)    \
{                                                                                                   \
        hpiq_get_idx_offset_lvl(4, __bitmap_type, bucket)                                                       \
        hpiq->bitmap_lvl_1 |= (__bitmap_type)(1 << __off4);                            \
        hpiq->bitmap_lvl_2[__off4] |= (__bitmap_type)(1 << __off3);                            \
        hpiq->bitmap_lvl_3[__off3] |= (__bitmap_type)(1 << __off2);                            \
        hpiq->bitmap_lvl_4[__off2] |= (__bitmap_type)(1 << __off1);                            \
}    
 
#define hpiq_insert_lvl(level, _name, __bitmap_type) hpiq_insert_lvl_##level(_name, __bitmap_type)

#define hpiq_delete_lvl_1(_name, __bitmap_type)                                              \
static __always_inline void hpiq_delete_lvl_1__##_name(struct hpiq__##_name *hpiq, __u32 bucket)    \
{                                                                                                   \
        hpiq_get_idx_offset_lvl(1, __bitmap_type, bucket)                                                       \
        hpiq->bitmap_lvl_1 &= ~(__bitmap_type)(1 << __off1);                            \
}    

#define hpiq_delete_lvl_2(_name, __bitmap_type)                                              \
static __always_inline void hpiq_delete_lvl_2__##_name(struct hpiq__##_name *hpiq, __u32 bucket)    \
{                                                                                                   \
        hpiq_get_idx_offset_lvl(2, __bitmap_type, bucket)                                                       \
        hpiq->bitmap_lvl_2[__off2] &= ~(__bitmap_type)(1 << __off1);                            \
        if (hpiq->bitmap_lvl_2[__off2] == 0)                                  \
                hpiq->bitmap_lvl_1 &= ~(__bitmap_type)(1 << __off2);                            \
} 

#define hpiq_delete_lvl_3(_name, __bitmap_type)                                              \
static __always_inline void hpiq_delete_lvl_3__##_name(struct hpiq__##_name *hpiq, __u32 bucket)    \
{                                                                                                   \
        hpiq_get_idx_offset_lvl(3, __bitmap_type, bucket)                                                       \
        hpiq->bitmap_lvl_3[__off2] &= ~(__bitmap_type)(1 << __off1);                            \
        if (hpiq->bitmap_lvl_3[__off2] == 0)                                  \
                hpiq->bitmap_lvl_2[__off3] &= ~(__bitmap_type)(1 << __off2);                            \
        if (hpiq->bitmap_lvl_2[__off3] == 0)                                  \
                hpiq->bitmap_lvl_1 &= ~(__bitmap_type)(1 << __off3);                            \
} 

#define hpiq_delete_lvl_4(_name, __bitmap_type)                                              \
static __always_inline void hpiq_delete_lvl_4__##_name(struct hpiq__##_name *hpiq, __u32 bucket)    \
{                                                                                                   \
        hpiq_get_idx_offset_lvl(4, __bitmap_type, bucket)                                                       \
        hpiq->bitmap_lvl_4[__off2] &= ~(__bitmap_type)(1 << __off1);                            \
        if (hpiq->bitmap_lvl_4[__off2] == 0)                                  \
                hpiq->bitmap_lvl_3[__off3] &= ~(__bitmap_type)(1 << __off2);                            \
        if (hpiq->bitmap_lvl_3[__off3] == 0)                                  \
                hpiq->bitmap_lvl_2[__off4] &= ~(__bitmap_type)(1 << __off3);                            \
        if (hpiq->bitmap_lvl_2[__off4] == 0)                                  \
                hpiq->bitmap_lvl_1 &= ~(__bitmap_type)(1 << __off4);                            \
} 

#define hpiq_delete_lvl(level, _name, __bitmap_type) hpiq_delete_lvl_##level(_name, __bitmap_type)

//x1 * HBITMAP_LEVEL(n-1) +  x2 * HBITMAP_LEVEL(n-2) + ....  xn 
/* should define PER_LONG_BITS_SHIFT for ffs*/
#define DECLARE_HPIQ(_name, level, __bitmap_type)                               \
struct hpiq__##_name {                  \
        DECLARE_HIE_PRIO_IDX_QUEUE_LVL(level, __bitmap_type)                    \
};                                                                              \
hpiq_front_idx_lvl(level, _name, __bitmap_type)                                                 \
static __always_inline __bitmap_type hpiq_front_idx__##_name(struct hpiq__##_name *hpiq)                \
{                                                               \
        return hpiq_front_idx_lvl_## level ##__ ## _name (hpiq);                                 \
}                                                                                               \
hpiq_insert_lvl(level, _name, __bitmap_type)                                                     \
static __always_inline void hpiq_insert__##_name(struct hpiq__##_name *hpiq, __u32 bucket)                \
{                                                               \
        return hpiq_insert_lvl_## level ##__ ## _name (hpiq, bucket);                                 \
}                                                                                                       \
hpiq_delete_lvl(level, _name, __bitmap_type)                                                     \
static __always_inline void hpiq_delete__##_name(struct hpiq__##_name *hpiq, __u32 bucket)                \
{                                                                                                               \
        return hpiq_delete_lvl_## level ##__ ## _name (hpiq, bucket);                                 \
}

DECLARE_HPIQ(cffs, 2, bitmap_type)

struct cffs_piq {
        struct hpiq__cffs hpiq[2];
        bool prime;
        __u32 h_index;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct simple_rbuf__pkt_bkt);  
	__uint(max_entries, 2 * HBITMAP_LEVEL(2));
} pkt_buf_percpu_map SEC(".maps");

#define BUCKET_NUM HBITMAP_LEVEL_2

static __noinline int cffs_enqueue(struct cffs_piq *cffs, void * bucket_buffer_map, __u32 prio, const struct __packet_type* pkt)
{
        if (unlikely(prio > (cffs->h_index + 2 * BUCKET_NUM))) {
                prio = cffs->h_index + 2 * BUCKET_NUM;
        } else if (unlikely(prio < cffs->h_index)) {
                prio = cffs->h_index;
        }
        prio -= cffs->h_index;  //bounded to [0, 2 * BUCKET_NUM], real prio is h_index + prio

        log_debug("bounded prio : %u", prio);
        //prime:True used_prime:True => True, prime:True, use_prime:False => False. prime:False, use_prime:True => False, prime: False, use_prime:False => True
        bool use_prime = (prio < (cffs->h_index + BUCKET_NUM));
        bool idx = !(use_prime ^ cffs->prime);
        __u32 __prio = prio - (!(use_prime)) * BUCKET_NUM;
        log_debug("use prime :%d, current prime: %d, cal idx :%d", use_prime, cffs->prime, idx);
        
        int key = (int)prio;
        log_debug("percpu bkt key: %d", key);
        log_debug("__prio: %u", __prio);

        struct simple_rbuf__pkt_bkt *pktbuf;
        pktbuf = bpf_map_lookup_elem(bucket_buffer_map, &key);
        if (pktbuf == NULL)
                return -1;
        //insert the packet to bucket ringbuf
        struct __packet_type *prod =  pkt_bkt__simple_rbuf_prod(pktbuf);
        if (prod == NULL)  
                return -2;       //ring buffer is full 
        asm_bound_check(idx, 2); //to make the verifier happy 
        hpiq_insert__cffs(&cffs->hpiq[idx], __prio);
        log_debug("cffs_enqueue: prime hpiq first level: %x", cffs->hpiq[idx].bitmap_lvl_1);
        __builtin_memcpy(prod, pkt, sizeof(*prod));
        pkt_bkt__simple_rbuf_submit(pktbuf);
        return 0;
}

static __noinline struct simple_rbuf__pkt_bkt* cffs_first_bkt(struct cffs_piq *cffs, void * bucket_buffer_map, __u32 *bktnum)
{
        bool prime = cffs->prime;
        asm_bound_check(prime, 2); 
        struct hpiq__cffs* phpiq = &cffs->hpiq[prime];
        if (unlikely(phpiq->bitmap_lvl_1) == 0) {
                struct hpiq__cffs *snd_hpiq = &cffs->hpiq[!prime];
                if (snd_hpiq->bitmap_lvl_1 == 0) {
                        //non packet 
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
        __u32 __bktnum  =(__u32)hpiq_front_idx__cffs(phpiq);
        log_debug("cffs_first_bkt: front bkt %u", __bktnum);
        int key = (int)cffs->prime * BUCKET_NUM + (int)(__bktnum);
        *bktnum = __bktnum;
        return bpf_map_lookup_elem(bucket_buffer_map, &key);
}

static __noinline void cffs_dequeue(struct cffs_piq *cffs, struct simple_rbuf__pkt_bkt * bucket_buffer, __u32 bktnum)
{
        /*bktnum is the retparam of cffs_first_bkt it should come from the primary hffs and should not be empty 
        * 1. unset hffs 
        * 2. consume ringbuffer 
        */
        bool prime = cffs->prime;
        asm_bound_check(prime, 2);
        hpiq_delete__cffs(&cffs->hpiq[prime], bktnum);
        if (cffs->hpiq[prime].bitmap_lvl_1 == 0) {
                //switch prime 
                cffs->prime = !(prime);
        }
        pkt_bkt__simple_rbuf_release(bucket_buffer);
}

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct cffs_piq);  
	__uint(max_entries, 1);
} cffs_piq_map SEC(".maps");


#define xdp_assert(expr, str)   \
({                               \
        if (unlikely(!(expr)))  {                            \
                log_error("[xdp assert failed]: %s %s", str);                  \
                goto xdp_error;                                         \
        };                                              \
})              

SEC("xdp")
int test_hffs1(struct xdp_md *ctx) {
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
        struct __packet_type pkt = {
                .data = (__u64)prio
        };
        log_debug("test insert prio %u", prio);
        res = cffs_enqueue(cffs, (void*)&pkt_buf_percpu_map, prio, &pkt);
        log_debug("cffs_enqueue res %d", res);
        xdp_assert((res == 0), "cffs enqueue failed");
        log_info("test1 success");

        //get the pkt right now
        __u32 bktnum = 0;
        pktbuf = cffs_first_bkt(cffs, (void*)&pkt_buf_percpu_map, &bktnum);
        log_debug("cffs_first_bkt, bktnum: %u", bktnum);
        xdp_assert((pktbuf != NULL), "cffs_first_bkt return NULL");

        //get ringbuffer 
        struct __packet_type *__pkt;
        __pkt = pkt_bkt__simple_rbuf_cons(pktbuf);
        xdp_assert((__pkt != NULL), "cffs first bucket ringbuffer is empty");
        xdp_assert((__pkt->data == pkt.data), "pkt is not the same");
        log_info("test2 success");

        //update the second prio in [BUCKET_NUM, 2*BUCKET_NUM)
        __u32 prio2 = (bpf_get_prandom_u32() % BUCKET_NUM) + BUCKET_NUM;
        struct __packet_type pkt2 = {
                .data = (__u64)prio2
        };
        res = cffs_enqueue(cffs, (void*)&pkt_buf_percpu_map, prio2, &pkt2);
        xdp_assert((res == 0), "cffs enqueue2 failed");
        log_info("test3 success");

        //dequeue the first one 
        cffs_dequeue(cffs, pktbuf, bktnum);
        xdp_assert((pkt_bkt__simple_rbuf_empty(pktbuf)), "ring buffer should be empty");
        xdp_assert((cffs->prime == 1), "prime not switching");
        log_info("test4 success");

        //lookup the current front 
        //get the pkt right now
        __u32 bktnum2 = 0;
        pktbuf2 = cffs_first_bkt(cffs, (void*)&pkt_buf_percpu_map, &bktnum2);
        log_debug("cffs_first_bkt2, bktnum2: %u", bktnum2);
        xdp_assert((cffs->prime == 1), "prime not switching");
        xdp_assert((pktbuf2 != NULL), "cffs_first_bkt2 return NULL");
        xdp_assert((bktnum2 == (prio2 - BUCKET_NUM)), "prio2 not correct");  
        struct __packet_type *__pkt2;
        __pkt2 = pkt_bkt__simple_rbuf_cons(pktbuf2);
        xdp_assert((__pkt2 != NULL), "cffs first bucket ringbuffer is empty");
        xdp_assert((__pkt2->data == pkt2.data), "pkt2 is not the same");
        log_info("test5 success");

        log_info("test all success");
        return XDP_PASS;
xdp_error:;
        //log_error("res: %d", res);
        return XDP_DROP;
}


