#ifndef EBPF_DEMO_COMMON_H
#define EBPF_DEMO_COMMON_H

#include "vmlinux.h"
#include <bpf_helpers.h>

#ifndef LOG_LEVEL
#define LOG_LEVEL 2
#endif 

#define LOG_LEVEL_DEBUG 3
#define LOG_LEVEL_INFO 2
#define LOG_LEVEL_WARN 1
#define LOG_LEVEL_ERROR 0 

// #define COLOR_RED "\033[0;31m"
// #define COLOR_GREEN "\033[0;32m"
// #define COLOR_YELLOW "\033[1;33m"
// #define COLOR_ORIGIN "\033[0;33m"
// #define COLOR_OFF "\033[0m" 

/*
*DEBUG: LEVEL=4
*INFO: LEVEL=3
*WARN: LEVEL=2
*ERROR: LEVEL=1
*/

#if LOG_LEVEL >= LOG_LEVEL_DEBUG			
	#define log_debug(FMT, ...)				\
	({										\
		bpf_printk("[DEBUG]" FMT, ##__VA_ARGS__);						\
	})										
#else
	#define log_debug(fmt, ...)	 ({})
#endif

#if LOG_LEVEL >= LOG_LEVEL_INFO			
	#define log_info(FMT, ...)											\
	({																	\
		bpf_printk("[INFO]" FMT, ##__VA_ARGS__);						\
	})										
#else
	#define log_info(fmt, ...)	 ({})									
#endif

#if LOG_LEVEL >= LOG_LEVEL_WARN			
	#define log_warn(FMT, ...)											\
	({																	\
		bpf_printk("[WARN]" FMT, ##__VA_ARGS__);						\
	})										
#else
	#define log_warn(fmt, ...)	 ({})									
#endif

#if LOG_LEVEL >= LOG_LEVEL_ERROR		
	#define log_error(FMT, ...)											\
	({																	\
		bpf_printk("[DEBUG]" FMT, ##__VA_ARGS__);						\
	})										
#else
	#define log_error(fmt, ...)	 ({})									
#endif

#ifndef likely
#define likely(X) __builtin_expect(!!(X), 1)
#endif

#ifndef unlikely
#define unlikely(X) __builtin_expect(!!(X), 0)
#endif

#ifndef build_bug_on
#define build_bug_on(E) ((void)sizeof(char[1 - 2 * !!(E)]))
#endif

#ifndef lock_xadd
#define lock_xadd(P, V) ((void)__sync_fetch_and_add((P), (V)))
#endif

#define LOG2(x)                                                                                    \
    ({                                                                                             \
        unsigned _x = (x);                                                                         \
        unsigned _result = 0;                                                                      \
        while (_x >>= 1) {                                                                         \
            _result++;                                                                             \
        }                                                                                          \
        _result;                                                                                   \
    })

#define SHIFT_TO_SIZE(_shift)  ((unsigned long)1 << (_shift))

#define BOUND_INDEX(idx, shift)			\
({typeof(idx) __idx; __idx = (idx) & (SHIFT_TO_SIZE(shift) - 1);})				

#define DECLARE_SIMPLE_RINGBUF(_name, _value_type, _size_shift)                  \
struct simple_rbuf__##_name {                                                 \
        _value_type data[SHIFT_TO_SIZE((_size_shift))];                                \
        __u64 cons;                                                             \
        __u64 prod;                                                             \
};                                                                              \
static __always_inline bool _name##__simple_rbuf_full(struct simple_rbuf__##_name *rb)    \
{                            \
        return (rb)->prod - (rb)->cons == SHIFT_TO_SIZE(_size_shift);                                           \
}                                                                                            \
static __always_inline bool _name##__simple_rbuf_empty(struct simple_rbuf__##_name *rb)        \
{                                                                                               \
        return (rb)->prod == (rb)->cons;                                                        \
}                                                                                               \
static __always_inline _value_type* _name##__simple_rbuf_cons(struct simple_rbuf__##_name *rb)   \
{                                                                               \
        if (unlikely(_name##__simple_rbuf_empty((rb)))) {                         \
                return NULL;   /*ringbuf is empty*/                              \
        } else {                                                                 \
                return &((rb)->data[BOUND_INDEX((rb)->cons, (_size_shift))]);   \
        }                                                                        \
}               \
static __always_inline void _name##__simple_rbuf_release(struct simple_rbuf__##_name *rb)        \
{                                                                       \
        ++((rb)->cons);                                                 \
}                                                                       \
static __always_inline _value_type* _name##__simple_rbuf_prod(struct simple_rbuf__##_name *rb)   \
{                                                                               \
        if (unlikely(_name##__simple_rbuf_full((rb)))) {                         \
                return NULL;   /*ringbuf is full*/                              \
        } else {                                                                 \
                return &((rb)->data[BOUND_INDEX((rb)->prod, (_size_shift))]);   \
        }                                                                        \
} \
static __always_inline void _name##__simple_rbuf_submit(struct simple_rbuf__##_name *rb)        \
{                                                                       \
        if (unlikely((rb)->prod == (~0UL))) {                                       \
                __u64 len = (rb)->prod - (rb)->cons;            \
                (rb)->cons = 0;                                 \
                (rb)->prod = len;                               \
        }                                                       \
        ++((rb)->prod);                                                 \
}             

/* linux __ffs software implementation*/
static __always_inline __u64 __ffs64(__u64 word)
{
	int num = 0;

	if ((word & 0xffffffff) == 0) {
		num += 32;
		word >>= 32;
	}
	if ((word & 0xffff) == 0) {
		num += 16;
		word >>= 16;
	}
	if ((word & 0xff) == 0) {
		num += 8;
		word >>= 8;
	}
	if ((word & 0xf) == 0) {
		num += 4;
		word >>= 4;
	}
	if ((word & 0x3) == 0) {
		num += 2;
		word >>= 2;
	}
	if ((word & 0x1) == 0)
		num += 1;
	return num;
}


static __always_inline __u32 __ffs32(__u32 word)
{
	int num = 0;
	if ((word & 0xffff) == 0) {
		num += 16;
		word >>= 16;
	}
	if ((word & 0xff) == 0) {
		num += 8;
		word >>= 8;
	}
	if ((word & 0xf) == 0) {
		num += 4;
		word >>= 4;
	}
	if ((word & 0x3) == 0) {
		num += 2;
		word >>= 2;
	}
	if ((word & 0x1) == 0)
		num += 1;
	return num;
}

#define STR(s) #s
#define XSTR(s) STR(s)

#define asm_bound_check(variable, max_size)     \
({      \
        asm volatile (  \
                "%[tmp] &= " XSTR(max_size - 1) " \n"   \
                :[tmp]"+&r"(variable)                   \
        );                                              \
})

#endif



