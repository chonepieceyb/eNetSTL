#pragma once 

#include "enetstl_apis.h"

/*TW implementation from linux 2.6.11*/

//#define TVN_BITS 6
//#define TVR_BITS 8

#ifndef TIME_SHIFT
#define TIME_SHIFT 12
#endif 

#if LOG_LEVEL > LOG_LEVEL_DEBUG
#define TVN_BITS 2
#define TVR_BITS 2
#else  
#define TVN_BITS 6
#define TVR_BITS 8
#endif 

#define TVN_SIZE (1 << TVN_BITS)
#define TVR_SIZE (1 << TVR_BITS)
#define TVN_MASK (TVN_SIZE - 1)
#define TVR_MASK (TVR_SIZE - 1)
#define TIMER_MAX_LOOKS 128

#define NUM_TIME_WHEELS 2
#if NUM_TIME_WHEELS < 2 || NUM_TIME_WHEELS > 5
#error NUM_TIME_WHEELS must be between 2 and 5
#endif

// #define TIMER_MAX_TIMEOUT (1 << (TVR_BITS + TVN_BITS * (NUM_TIME_WHEELS - 1)))
#define TIMER_MAX_TIMEOUT 512

#define MAX_LOOP ((u32)20000)

#define time_after(a,b)		\
	(typecheck(unsigned long, a) && \
	 typecheck(unsigned long, b) && \
	 ((long)(b) - (long)(a) < 0))
#define time_before(a,b)	time_after(b,a)

#define time_after_eq(a,b)	\
	(typecheck(unsigned long, a) && \
	 typecheck(unsigned long, b) && \
	 ((long)(a) - (long)(b) >= 0))
#define time_before_eq(a,b)	time_after_eq(b,a)

PACKET_COUNT_MAP_DEFINE

/*elem of the time list*/

struct bpf_time_list {
        unsigned long expires;
};

struct time_wheel_queue {
        unsigned long clk;
        __u32 cnt; 
        int init;
	
};

struct bktlists {
        int fd;
        struct bpf_bkt_list __kptr *map;  
};

#if LOG_LEVEL > LOG_LEVEL_DEBUG
unsigned long current_time_g = 0;
#endif 

static __always_inline unsigned long get_current_time() {
#if LOG_LEVEL > LOG_LEVEL_DEBUG
	return current_time_g;
#else  
	//return (unsigned long)bpf_jiffies64();
        //current per 256ns is one tick
        return (unsigned long)bpf_ktime_get_ns() >> TIME_SHIFT;
#endif 
}

static __always_inline int __add_timer_on(struct time_wheel_queue *base, 
						int timer_bkt_map, unsigned long expires,  struct bpf_time_list* time_list) {
	unsigned long idx = expires - base->clk;
        struct time_wheel_bkt_list *tl; 
	int i, res;

    if (idx < TVR_SIZE) {
        i = expires & TVR_MASK;
        log_debug("add timer to lv1 index %d", i);
    } else if (idx < 1 << (TVR_BITS + TVN_BITS)) {
        i = ((expires >> TVR_BITS) & TVN_MASK) + TVR_SIZE;      /*index is lv1 + offset in lv2*/
        log_debug("add timer to lv2 index %d", i);
#if NUM_TIME_WHEELS >= 3
	} else if (idx < 1 << (TVR_BITS + 2 * TVN_BITS)) {
		i = ((expires >> (TVR_BITS + TVN_BITS)) & TVN_MASK) + TVR_SIZE +
		    TVN_SIZE;
		log_debug("add timer to lv3 index %d", i);
#if NUM_TIME_WHEELS >= 4
	} else if (idx < 1 << (TVR_BITS + 3 * TVN_BITS)) {
		i = ((expires >> (TVR_BITS + 2 * TVN_BITS)) & TVN_MASK) +
		    TVR_SIZE + 2 * TVN_SIZE;
		log_debug("add timer to lv4 index %d", i);
#endif
#endif
	} else if ((signed long)idx < 0) {
		i = (base->clk & TVR_MASK);
		log_warn("idx < 0 add timer to current clk %d", i);
	} else {
#if NUM_TIME_WHEELS == 2
		expires = base->clk + (1 << (TVR_BITS + TVN_BITS)) - 1;
                i = ((expires >> TVR_BITS) & TVN_MASK) + TVR_SIZE;
		log_warn("add timer to lv2(max) index %d", i);
#elif NUM_TIME_WHEELS == 3
		expires = base->clk + (1 << (TVR_BITS + 2 * TVN_BITS)) - 1;
		i = ((expires >> (TVR_BITS + TVN_BITS)) & TVN_MASK) + TVR_SIZE +
		    TVN_SIZE;
		log_warn("add timer to lv3(max) index %d", i);
#else /* NUM_TIME_WHEELS >= 4 */
		expires = base->clk + (1 << (TVR_BITS + 3 * TVN_BITS)) - 1;
#if NUM_TIME_WHEELS == 4
		i = ((expires >> (TVR_BITS + 2 * TVN_BITS)) & TVN_MASK) +
		    TVR_SIZE + 2 * TVN_SIZE;
		log_warn("add timer to lv4(max) index %d", i);
#else /* NUM_TIME_WHEELS == 5 */
		i = ((expires >> (TVR_BITS + 3 * TVN_BITS)) & TVN_MASK) +
		    TVR_SIZE + 3 * TVN_SIZE;
		log_warn("add timer to lv5(max) index %d", i);
#endif
#endif
	}
    log_debug("add timer on slot %d, fd %d", i, timer_bkt_map);
    res = bpf_bktlist_push_back(timer_bkt_map, (void*)(time_list), sizeof(u64), i);
    if (res ==0)
        base->cnt += 1;
	return res;
}

struct __run_timerlist_ctx {
        int timer_bkt_map;
	struct time_wheel_queue *twq;
        u64 idx;
};

/*impl expires action here*/
static int __run_timerlist_loop(u32 index, void *ctx) {
        struct __run_timerlist_ctx *__ctx = (struct __run_timerlist_ctx*)ctx;
        struct bpf_time_list elem;
	__builtin_memset(&elem, 0, sizeof(elem));
	int res; 
        /* pop node from list*/
	res = bpf_bktlist_pop_front(__ctx->timer_bkt_map, (void*)&elem, sizeof(u64), __ctx->idx);
    if (res == 1) {
            /*skip the loop, empty*/
            log_debug("time slot is empty");
            return 1;
    }
    log_debug("time expires %lu", elem.expires);
	__ctx->twq->cnt -= 1;
    return 0;
}

struct __cascade_ctx {
        int	timer_bkt_map;
	struct time_wheel_queue *twq;
        u64 idx;
	int res;
};

static int __cascade_loop(u32 index, void *ctx) {
    struct __cascade_ctx *__ctx = (struct __cascade_ctx*)ctx;
	int res;
    struct bpf_time_list elem;
	__builtin_memset(&elem, 0, sizeof(elem));
    struct time_wheel_queue *twq = __ctx->twq;
        /* get the front elem*/
	res = bpf_bktlist_pop_front(__ctx->timer_bkt_map, (void*)&elem, sizeof(u64), __ctx->idx);
    if (res == 1) {
        /* empty */
        log_debug("cascade loop, time slot is empty");
        return 1; 
	} 
        
    /*** get the elem ******/
	__ctx->twq->cnt -= 1;
	/*re add to timer*/
    res = __add_timer_on(twq, __ctx->timer_bkt_map, elem.expires, &elem);
    if (res < 0) {
            log_error("failed to re add to timer");
            __ctx->res = -1;
            return 1;
    }
	log_debug("cascade elem to up level, clk %lu", twq->clk);
    return 0;
}

static int cascade(struct time_wheel_queue *base, int timer_bkt_map, int idx_off, int idx_base)
{
	/* cascade all the timers from tv up one level */
    struct time_wheel_bkt_list *tl;
	int res; 
    struct __cascade_ctx ctx = {
        .timer_bkt_map = timer_bkt_map,
        .twq = base,
        .idx = (idx_base + idx_off),
        res = 0,
    };

	res = bpf_loop(min(base->cnt, MAX_LOOP), &__cascade_loop, &ctx, 0);
	if (unlikely(res < 0 || ctx.res < 0)) {
		log_error(" failed to run bpf_loop, res: %d, ctx res: %d", res, ctx.res);
		return res; 
	}
	return idx_off;
}

#define INDEX(N) (base->clk >> (TVR_BITS + N * TVN_BITS)) & TVN_MASK

static int __run_timer(struct time_wheel_queue *base, int timer_bkt_map) {

        unsigned long current_time = get_current_time();
        int __i, res, should_warn = true; 
	    log_debug("__run_timer current time %lu", current_time);
        for (__i = 0; __i < TIMER_MAX_LOOKS; __i++) {
            if (time_before(current_time, base->clk)) {
                should_warn = false;
                break;
            }
            struct time_wheel_bkt_list *tl;
            int index = base->clk  & TVR_MASK;  /*current timer bkt idx*/

            if (index) {
            } else if (cascade(base, timer_bkt_map, INDEX(0), TVR_SIZE)) {
    #if NUM_TIME_WHEELS >= 3
            } else if (cascade(base, timer_bkt_map, INDEX(1),
                    TVR_SIZE + TVN_SIZE)) {
    #if NUM_TIME_WHEELS >= 4
            } else if (cascade(base, timer_bkt_map, INDEX(2),
                    TVR_SIZE + 2 * TVN_SIZE)) {
    #if NUM_TIME_WHEELS >= 5
            } else if (cascade(base, timer_bkt_map, INDEX(3),
                    TVR_SIZE + 3 * TVN_SIZE)) {
    #endif
    #endif
    #endif
                log_debug("cascade max level returned non-zero");
            }

            struct __run_timerlist_ctx ctx = {
                .timer_bkt_map = timer_bkt_map,
                .twq = base,
                .idx = index,
            };
                    /* travel the work list*/
            res = bpf_loop(min(base->cnt, MAX_LOOP), &__run_timerlist_loop, &ctx, 0);
            if (res < 0) {
                log_error(" failed to run bpf_loop");
                return res; 
            }
            base->clk += 1;
            log_debug("__run_timer plus 1 tick: bpf_loop clk index %d run %d times", index, res);
        }
	    if (unlikely(should_warn)) 
		    log_warn("time wheel faild to catch up ticks: current time %lu, clk: %lu", current_time, base->clk);
        return 0;
}
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct bktlists);  
	__uint(max_entries, 1);
} bpf_bktlist_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct time_wheel_queue);  
	__uint(max_entries, 1);
} time_wheel_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, u64);
	__uint(max_entries, 1);
} num_runs_map SEC(".maps");