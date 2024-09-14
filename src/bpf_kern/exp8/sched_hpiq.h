#ifndef __SCHED_HPIQ_H
#define __SCHED_HPIQ_H

#include "../common.h"

#ifndef BITMAP_TYPE
typedef __u32 bitmap_type;
#define PER_LONG_BITS_SHIFT 5
#define __ffs __ffs64
#define BITS_PER_LONG 32
#endif

#define __inline __noinline

#ifndef PKT_BKT_SIZE_SHIFT
#define PKT_BKT_SIZE_SHIFT 8
#endif

#ifndef PKT_BKT_SIZE
#define PKT_BKT_SIZE SHIFT_TO_SIZE(PKT_BKT_SIZE_SHIFT)
#endif

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
	__bitmap_type __idx1 =                   \
		BOUND_INDEX(__ffs(hpiq->bitmap_lvl_1), PER_LONG_BITS_SHIFT);

#define hpiq_cal_idx_lvl_2(_name, __bitmap_type)                        \
	hpiq_cal_idx_lvl_1(_name, __bitmap_type) __bitmap_type __idx2 = \
		BOUND_INDEX(__ffs(hpiq->bitmap_lvl_2[__idx1]),          \
			    PER_LONG_BITS_SHIFT);

#define hpiq_cal_idx_lvl_3(_name, __bitmap_type)                        \
	hpiq_cal_idx_lvl_2(_name, __bitmap_type) __bitmap_type __idx3 = \
		BOUND_INDEX(__ffs(hpiq->bitmap_lvl_3[__idx2]),          \
			    PER_LONG_BITS_SHIFT);

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

#endif