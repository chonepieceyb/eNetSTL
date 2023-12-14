#include "common.h"
#include "vmlinux.h"

char _license[] SEC("license") = "GPL";

/***********************************************
*********************PKTBKT PERCPU**************
************************************************/

typedef __u64 bitmap_type;
#define PER_LONG_BITS_SHIFT 6  //64 per long
#define __ffs __ffs64
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
        __bitmap_type bitmap_lvl_2[HBITMAP_LEVEL_2];

#define DECLARE_HIE_PRIO_IDX_QUEUE_LVL_3(__bitmap_type)               \
        DECLARE_HIE_PRIO_IDX_QUEUE_LVL_2(__bitmap_type)                 \
        __bitmap_type bitmap_lvl_3[HBITMAP_LEVEL_3];

#define DECLARE_HIE_PRIO_IDX_QUEUE_LVL_4(__bitmap_type)               \
        DECLARE_HIE_PRIO_IDX_QUEUE_LVL_3(__bitmap_type)                 \
        __bitmap_type bitmap_lvl_4[HBITMAP_LEVEL_4];


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
 
//x1 * HBITMAP_LEVEL(n-1) +  x2 * HBITMAP_LEVEL(n-2) + ....  xn 
/* should define BITS_PER_LONG for ffs*/
#define DECLARE_HPIQ(_name, level, __bitmap_type)                               \
struct hpiq__##_name {                  \
        DECLARE_HIE_PRIO_IDX_QUEUE_LVL(level, __bitmap_type)                    \
};                                                                              \
hpiq_front_idx_lvl(level, _name, __bitmap_type)                                                 \
static __always_inline __bitmap_type hpiq_front_idx__##_name(struct hpiq__##_name *hpiq)                \
{                                                               \
        return hpiq_front_idx_lvl_## level ##__ ## _name (hpiq);                                 \
}

DECLARE_HPIQ(hpiq, 2, bitmap_type)

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct simple_rbuf__pkt_bkt);  
	__uint(max_entries, 2 * HBITMAP_LEVEL(2));
} pkt_buf_percpu_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct simple_rbuf__pkt_bkt);  
	__uint(max_entries, 1);
} cffs_piq_map SEC(".maps");

SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
        log_info("xdp_empty %d", 1);
        return XDP_PASS;
}

