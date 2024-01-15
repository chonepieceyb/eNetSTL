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
		bpf_printk("[ERROR]" FMT, ##__VA_ARGS__);						\
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

#define xdp_assert(expr, name)   \
({                               \
        if (unlikely(!(expr)))  {                            \
                log_error("[xdp assert failed]: unexpected %s", name);                  \
                goto xdp_error;                                         \
        };                                              \
})  

#define xdp_assert_eq(expected, actual, name)   \
({                               				                                                                                            \
	typeof(actual) ___act = (actual);				                                                                                    \
	typeof(expected) ___exp = (expected);				                                                                                    \
	bool ___ok = ___act == ___exp;					                                                                                    \
        if (unlikely(!___ok))  {                                                                                                                            \
                log_error("[xdp assert failed]: unexpected %s: actual %lld != expected %lld\n", name, (long long)___act, (long long)___exp);                  \
                goto xdp_error;                                                                                                                             \
        };                                                                                                                                                  \
}) 

#define xdp_assert_neq(noexpected, actual, name)   \
({                               				                                                                                            \
	typeof(actual) ___act = (actual);				                                                                                    \
	typeof(noexpected) ___noexp = (noexpected);				                                                                                    \
	bool ___ok = ___act != ___noexp;					                                                                                    \
        if (unlikely(!___ok))  {                                                                                                                            \
                log_error("[xdp assert failed]: unexpected %s: actual %lld == non expected %lld\n", name, (long long)___act, (long long)___noexp);                  \
                goto xdp_error;                                                                                                                             \
        };                                                                                                                                                  \
}) 

#define xdp_assert_tag(expr, name, tag)   \
({                               \
        if (unlikely(!(expr)))  {                            \
                log_error("[xdp assert failed]: unexpected %s", name);                  \
                goto tag;                                         \
        };                                              \
})  

#define xdp_assert_eq_tag(expected, actual, name, tag)   \
({                               				                                                                                            \
	typeof(actual) ___act = (actual);				                                                                                    \
	typeof(expected) ___exp = (expected);				                                                                                    \
	bool ___ok = ___act == ___exp;					                                                                                    \
        if (unlikely(!___ok))  {                                                                                                                            \
                log_error("[xdp assert failed]: unexpected %s: actual %lld != expected %lld\n", name, (long long)___act, (long long)___exp);                  \
                goto tag;                                                                                                                             \
        };                                                                                                                                                  \
}) 

#define xdp_assert_neq_tag(noexpected, actual, name, tag)   \
({                               				                                                                                            \
	typeof(actual) ___act = (actual);				                                                                                    \
	typeof(noexpected) ___noexp = (noexpected);				                                                                                    \
	bool ___ok = ___act != ___noexp;					                                                                                    \
        if (unlikely(!___ok))  {                                                                                                                            \
                log_error("[xdp assert failed]: unexpected %s: actual %lld == non expected %lld\n", name, (long long)___act, (long long)___noexp);                  \
                goto tag;                                                                                                                             \
        };                                                                                                                                                  \
}) 



#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })
 
#define max(x, y) ({				\
	typeof(x) _max1 = (x);			\
	typeof(y) _max2 = (y);			\
	(void) (&_max1 == &_max2);		\
	_max1 > _max2 ? _max1 : _max2; })

#define typecheck(type,x) \
({	type __dummy; \
	typeof(x) __dummy2; \
	(void)(&__dummy == &__dummy2); \
	1; \
})


#endif



