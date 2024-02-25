#include "../common.h"

char _license[] SEC("license") = "GPL";

/********************************************/
/**************TW defines********************
**********************************************/

/*TW implementation from linux 2.6.11*/

//#define TVN_BITS 6
//#define TVR_BITS 8

#define TIME_SHIFT 13

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

#define BKT_NUM_PER_CPU (TVR_SIZE + TVN_SIZE * (NUM_TIME_WHEELS - 1))
/*elem of the time list*/

#define FRONT_TAIL_BIT_POS 0     //bit pos, set means front 
#define INS_LOOK_BIT_POS 1     //bit pos, set means insert

#define bktlist_lookup_flag(ins_look, front_tail)			\
({									\
	u32 __flags = 0;						\
	u32 __ins_look = !!(ins_look);					\
	u32 __front_tail = !!(front_tail);				\
	__flags |= (__ins_look << INS_LOOK_BIT_POS);			\
	__flags |= (__front_tail << FRONT_TAIL_BIT_POS);		\
})

#define bktlist_delete_flag(front_tail)				        \
({									\
	u32 __flags = 0;						\
	u32 __front_tail = !!(front_tail);				\
	__flags |= (__front_tail << FRONT_TAIL_BIT_POS);			\
})

#define bktlist_flag_lookup_front  bktlist_lookup_flag(0, 1)
#define bktlist_flag_lookup_tail   bktlist_lookup_flag(0, 0)
#define bktlist_flag_ins_front  bktlist_lookup_flag(1, 1)
#define bktlist_flag_ins_tail	bktlist_lookup_flag(1, 0)
#define bktlist_flag_delete_front	bktlist_delete_flag(1)
#define bktlist_flag_delete_tail	bktlist_delete_flag(0)

struct __bktlist_key_type {
	u32 idx;
	u32 flags; 
};

struct bpf_time_list {
        unsigned long expires;
};

struct time_wheel_queue {
        unsigned long clk;
        __u32 cnt; 
        int init;
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

static __always_inline struct bpf_time_list* __add_timer_on(struct time_wheel_queue *base, void *timer_bkt_map, unsigned long expires) {
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

        struct __bktlist_key_type key = {
                .idx = i,
                .flags = bktlist_flag_ins_tail,
        };
	return bpf_map_lookup_elem(timer_bkt_map, &key);
        //base->cnt += 1;
}

struct __run_timerlist_ctx {
        void   *timer_bkt_map;
	struct time_wheel_queue *twq;
        struct __bktlist_key_type key;
};

/*impl expires action here*/
static int __run_timerlist_loop(u32 index, void *ctx) {
        struct __run_timerlist_ctx *__ctx = (struct __run_timerlist_ctx*)ctx;
        struct bpf_time_list *elem;

        /* pop node from list*/
        elem = bpf_map_lookup_elem(__ctx->timer_bkt_map, &__ctx->key);
        if (elem == NULL) {
                /*skip the loop*/
                return 1;
        }
        /*** get the elem ******/
        /*run timer function here*/
        log_debug("pop elem expires %lu", elem->expires);
        bpf_map_delete_elem(__ctx->timer_bkt_map, &__ctx->key);
	__ctx->twq->cnt -= 1;
        return 0;
}

struct __cascade_ctx {
        void   *timer_bkt_map;
	struct time_wheel_queue *twq;
        struct __bktlist_key_type key;
	int res;
};

static int __cascade_loop(u32 index, void *ctx) {
        struct __cascade_ctx *__ctx = (struct __cascade_ctx*)ctx;
	int res;
        struct bpf_time_list *elem, *new_elem;
        struct time_wheel_queue *twq = __ctx->twq;
        /* get the front elem*/
        elem = bpf_map_lookup_elem(__ctx->timer_bkt_map, &__ctx->key);
        if (elem == NULL) {
                /* empty */
                return 1; 
        }
        
        /*** get the elem ******/
	__ctx->twq->cnt -= 1;
	/*re add to timer*/
        new_elem = __add_timer_on(twq, __ctx->timer_bkt_map, elem->expires);
        if (new_elem == NULL) {
                log_error("failed to re add to timer");
                __ctx->res = -1;
                return 1;
        }
        __builtin_memcpy(new_elem, elem, sizeof(*new_elem));
        /*pop the front elem*/
        bpf_map_delete_elem(__ctx->timer_bkt_map, &__ctx->key);
	log_debug("cascade elem to up level, clk %lu", twq->clk);
        return 0;
}

static int cascade(struct time_wheel_queue *base, void *timer_bkt_map, int idx_off, int idx_base)
{
	/* cascade all the timers from tv up one level */
        struct time_wheel_bkt_list *tl;
	int res; 
        struct __cascade_ctx ctx = {
                .timer_bkt_map = timer_bkt_map,
                .twq = base,
                .key = {
                        .idx = (idx_base + idx_off),
                        .flags = bktlist_flag_delete_front,
                },
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

static int __run_timer(struct time_wheel_queue *base, void *timer_bkt_map) {

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
                        .key = {
                             .idx = index, 
                             .flags = bktlist_flag_delete_front,
                        }
                };
                /* travel the work list*/
		res = bpf_loop(min(base->cnt, MAX_LOOP), &__run_timerlist_loop,
			       &ctx, 0);
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
	__uint(type, BPF_MAP_TYPE_STATIC_CUSTOM_MAP);
	__type(key, struct __bktlist_key_type);
	__type(value, struct bpf_time_list);  
	__uint(max_entries, BKT_NUM_PER_CPU);
} timer_bkt SEC(".maps");

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

SEC("tc")
int test_timewheel(void *ctx)
{
	int key = 0, res;
	unsigned long ct = get_current_time();
	struct time_wheel_queue *twq;
	twq = bpf_map_lookup_elem(&time_wheel_map, &key);
	xdp_assert_neq(NULL, twq, "failed to lookup time_wheel_map");

	log_debug("init current time %lu", ct);
	twq->cnt = 0;
	twq->clk = ct;
	twq->init = 1;

        unsigned long expires = ct + 4;
        struct bpf_time_list *timer = __add_timer_on(twq, &timer_bkt, expires);
        xdp_assert_neq(NULL, timer, "__add_timer_on failed");
        timer->expires = expires;
	twq->cnt += 1;
	#if LOG_LEVEL > LOG_LEVEL_DEBUG
		current_time_g += 4;
	#endif 
        
        res = __run_timer(twq, &timer_bkt);
	xdp_assert_eq(0, res, "failed run timer");
	log_debug("current clk  %lu", twq->clk);
        log_debug("test success");
	return 0;
xdp_error:;
	return 1;
}

/*for performance testing*/
SEC("xdp")
int xdp_main(void *ctx)
{
	int key = 0, res;
	unsigned long ct = get_current_time();
	struct time_wheel_queue *twq;
	u64 num_runs, *num_runs_ptr;

	twq = bpf_map_lookup_elem(&time_wheel_map, &key);
	xdp_assert_neq(NULL, twq, "failed to lookup time_wheel_map");

	log_debug("init current time %lu", ct);
	if (unlikely(!twq->init)) {
                twq->cnt = 0;
                twq->clk = ct;
                twq->init = 1;
        }

	num_runs_ptr = bpf_map_lookup_elem(&num_runs_map, &key);
	xdp_assert_neq(NULL, num_runs_ptr, "failed to lookup num_runs_map");
	num_runs = *num_runs_ptr + 1;
	*num_runs_ptr = num_runs;

	log_debug("num runs %llu, timeout %u", num_runs,
		  num_runs & (TIMER_MAX_TIMEOUT - 1));

	unsigned long expires = ct + (num_runs & (TIMER_MAX_TIMEOUT - 1));
	struct bpf_time_list *timer = __add_timer_on(twq, &timer_bkt, expires);
	xdp_assert_neq(NULL, timer, "__add_timer_on failed");
        timer->expires = expires;
        twq->cnt += 1;
        
        res = __run_timer(twq, &timer_bkt);
	xdp_assert_eq(0, res, "failed run timer");
	log_debug("current clk  %lu", twq->clk);
	return XDP_DROP;

xdp_error:;
	return XDP_DROP;
}