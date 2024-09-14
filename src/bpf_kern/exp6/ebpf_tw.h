#include "../common.h"
#include "../bpf_experimental.h"

/********************************************/
/**************TW defines********************
**********************************************/

/*TW implementation from linux 2.6.11*/

//#define TVN_BITS 6
//#define TVR_BITS 8

#ifndef TIME_SHIFT
#define TIME_SHIFT 13
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
#define CPU_NUM 40

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


/* Two level time wheel*/

#define BKT_NUM_PER_CPU (TVR_SIZE + TVN_SIZE * (NUM_TIME_WHEELS - 1))

/*elem of the time list*/
struct bpf_time_list {
        struct bpf_list_node node; 
        unsigned long expires;
};

struct time_wheel_bkt_list {
	struct bpf_list_head head __contains(bpf_time_list, node);
	struct bpf_spin_lock lock;
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

static int add_timer_on(__u32 cpu, struct time_wheel_queue *base, void *timer_bkt_map, struct bpf_time_list *elem) {
	unsigned long expires = elem->expires;
	unsigned long idx = expires - base->clk;
        struct time_wheel_bkt_list *tl; 
	int i, key, res;

        if (idx < TVR_SIZE) {
                i = expires & TVR_MASK;
		log_debug("add timer to lv1 index %d", i);
        } else if (idx < 1 << (TVR_BITS + TVN_BITS)) {
		i = ((expires >> TVR_BITS) & TVN_MASK) + TVR_SIZE;      /*index is lv1 + offset in lv2*/
		log_debug("add timer to lv2 index %d", i);
#if NUM_TIME_WHEELS >= 3
	} else if (idx < (1 << (TVR_BITS + 2 * TVN_BITS))) {
		i = ((expires >> (TVR_BITS + TVN_BITS)) & TVN_MASK) + TVR_SIZE +
		    TVN_SIZE;
		log_debug("add timer to lv3 index %d", i);
#if NUM_TIME_WHEELS >= 4
	} else if (idx < (1 << (TVR_BITS + 3 * TVN_BITS))) {
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
		    TVR_SIZE;
		log_warn("add timer to lv5(max) index %d", i);
#endif
#endif
	}

	key = cpu * BKT_NUM_PER_CPU + i;
	tl = bpf_map_lookup_elem(timer_bkt_map, &key);
	if (tl == NULL) {
		log_error("internal_add_timer failed to lookup timer_bkt_map with key %d", key);
		return -1;
	}

	bpf_spin_lock(&tl->lock);
	res = bpf_list_push_back(&tl->head, &elem->node);
	bpf_spin_unlock(&tl->lock);

	if (res < 0) {
		log_error("failed to push list back res: %d", res);
		return -22; 
	}
	base->cnt += 1;
        return 0;
}

struct __run_timerlist_ctx {
        struct bpf_list_head *head; 
	struct bpf_spin_lock *lock;
	struct time_wheel_queue *twq;
};


/*impl expires action here*/
static int __run_timerlist_loop(u32 index, void *ctx) {
        struct __run_timerlist_ctx *__ctx = (struct __run_timerlist_ctx*)ctx;
        struct bpf_list_node *n;
        struct bpf_time_list *elem;

        /* pop node from list*/
	bpf_spin_lock(__ctx->lock);
        n = bpf_list_pop_front(__ctx->head);
	bpf_spin_unlock(__ctx->lock);

        if (n == NULL) {
                /*skip the loop*/
                return 1;
        }
        elem = container_of(n, struct bpf_time_list, node);
        
        /*** get the elem ******/
        log_debug("pop elem expires %lu", elem->expires);
        bpf_obj_drop(elem);
	__ctx->twq->cnt -= 1;
        return 0;
}

struct __cascade_ctx {
	struct time_wheel_queue *twq;
	struct time_wheel_bkt_list *tl; 
	void *timer_bkt_map;
	__u32 cpu;
	int res;
};

static int __cascade_loop(u32 index, void *ctx) {
        struct __cascade_ctx *__ctx = (struct __cascade_ctx*)ctx;\
	struct time_wheel_bkt_list *tl = __ctx->tl;
	struct time_wheel_queue *twq = __ctx->twq;
        struct bpf_list_node *n;
        struct bpf_time_list *elem;
	int res;

        /* pop node from list*/
	bpf_spin_lock(&tl->lock);
        n = bpf_list_pop_front(&tl->head);
	bpf_spin_unlock(&tl->lock);

        if (n == NULL) {
                /*skip the loop*/
                return 1;
        }
        elem = container_of(n, struct bpf_time_list, node);
        
        /*** get the elem ******/
	__ctx->twq->cnt -= 1;
	/*re add to timer*/
	res = add_timer_on(__ctx->cpu, twq, __ctx->timer_bkt_map, elem);
	if (res != 0 ) {
		if (res != -22)
			bpf_obj_drop(elem);
		log_error("failed to re add to timer res: %d", res);
		__ctx->res = res;  /*failed*/
		return 1;
	}
	log_debug("cascade elem to up level, clk %lu", twq->clk);
	__ctx->twq->cnt += 1;
        return 0;
}

static int cascade(__u32 cpu, struct time_wheel_queue *base, void *timer_bkt_map, int idx_off, int idx_base)
{
	/* cascade all the timers from tv up one level */
        struct time_wheel_bkt_list *tl; 
	int key = cpu * BKT_NUM_PER_CPU + (idx_base + idx_off);
	int res; 
	tl = bpf_map_lookup_elem(timer_bkt_map, &key);
	if (tl == NULL) {
		log_error("cascade failed to lookup bkt with key %d", key);
		return -1; 
	}

	struct __cascade_ctx ctx = {
		.twq = base,
		.tl = tl,
		.timer_bkt_map = timer_bkt_map,
		.cpu = cpu,
		.res = 0,
	};

	res = bpf_loop(min(base->cnt, MAX_LOOP), &__cascade_loop, &ctx, 0);
	if (res < 0 || ctx.res < 0) {
		log_error(" failed to run bpf_loop, res: %d, ctx res: %d", res, ctx.res);
		return res; 
	}
	return idx_off;
}

#define INDEX(N) (base->clk >> (TVR_BITS + N * TVN_BITS)) & TVN_MASK

static int __run_timer(__u32 cpu, struct time_wheel_queue *base, void *timer_bkt_map) {

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
		} else if (cascade(cpu, base, timer_bkt_map, INDEX(0),
				   TVR_SIZE)) {
#if NUM_TIME_WHEELS >= 3
		} else if (cascade(cpu, base, timer_bkt_map, INDEX(1),
				   TVN_SIZE + TVR_SIZE)) {
#if NUM_TIME_WHEELS >= 4
		} else if (cascade(cpu, base, timer_bkt_map, INDEX(2),
				   2 * TVN_SIZE + TVR_SIZE)) {
#if NUM_TIME_WHEELS >= 5
		} else if (cascade(cpu, base, timer_bkt_map, INDEX(3),
				   3 * TVN_SIZE + TVR_SIZE)) {
#endif
#endif
#endif
			log_debug("cascade max level returned non-zero");
		}

		int key = cpu * BKT_NUM_PER_CPU + index; 
		tl = bpf_map_lookup_elem(timer_bkt_map, &key);
		if (tl == NULL) {
			log_error("__run_timer failed to lookup timer_bkt_map with key %d", key);
			return -1; 
		}

                /* travel the work list*/
                struct __run_timerlist_ctx ctx;
                ctx.head = &tl->head;
		ctx.lock = &tl->lock;
		ctx.twq = base;
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
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct time_wheel_queue);  
	__uint(max_entries, 1);
} time_wheel_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct time_wheel_bkt_list);  
	__uint(max_entries, CPU_NUM * BKT_NUM_PER_CPU);
} time_wheel_bkt_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, u64);
	__uint(max_entries, 1);
} num_runs_map SEC(".maps");

// SEC("tc")
// int test_timewheel(void *ctx)
// {
// 	__u64 begin_time = bpf_ktime_get_ns();
// 	int key = 0, res;
// 	__u32 cpu = bpf_get_smp_processor_id();
// 	unsigned long ct = get_current_time();
// 	struct time_wheel_queue *tq;
// 	tq = bpf_map_lookup_elem(&time_wheel_map, &key);
// 	xdp_assert_neq(NULL, tq, "failed to lookup time_wheel_map");

// 	log_debug("init current time %lu", ct);
// 	tq->cnt = 0;
// 	tq->clk = ct;
// 	tq->init = 1;

// 	struct bpf_time_list *elem;
// 	elem = bpf_obj_new(typeof(*elem));
// 	xdp_assert_neq(NULL, elem, "elem = bpf_obj_new() failed ");

// 	elem->expires = ct + 2;
	
// 	res = add_timer_on(cpu, tq, &time_wheel_bkt_map, elem);
// 	if (res != 0 && res != -22) {
// 		bpf_obj_drop(elem);
// 	}
// 	xdp_assert_eq(0, res, "failed add timer");

// 	res = __run_timer(cpu, tq, &time_wheel_bkt_map);
// 	xdp_assert_eq(0, res, "failed run timer");
// 	log_debug("current clk  %lu", tq->clk);
// 	__u64 end_time = bpf_ktime_get_ns();
// 	log_info("init clk: %lu, curr clk: %lu, test1 cost %lu", ct, tq->clk, end_time - begin_time);
// 	return 0;

// xdp_error:;
// 	return 1;
// }

// SEC("tc")
// int test_timewheel2(void *ctx)
// {
// 	int key = 0, res;
// 	__u32 cpu = bpf_get_smp_processor_id();
// 	unsigned long ct = get_current_time();
// 	struct time_wheel_queue *tq;
// 	tq = bpf_map_lookup_elem(&time_wheel_map, &key);
// 	xdp_assert_neq(NULL, tq, "failed to lookup time_wheel_map");

// 	log_debug("init current time %lu", ct);
// 	tq->cnt = 0;
// 	tq->clk = ct;
// 	tq->init = 1;

// 	struct bpf_time_list *elem;
// 	elem = bpf_obj_new(typeof(*elem));
// 	xdp_assert_neq(NULL, elem, "elem = bpf_obj_new() failed ");

// 	elem->expires = ct + 4;
	
// 	res = add_timer_on(cpu, tq, &time_wheel_bkt_map, elem);
// 	if (res != 0 && res != -22) {
// 		bpf_obj_drop(elem);
// 	}
// 	xdp_assert_eq(0, res, "failed add timer");
	
// 	#if LOG_LEVEL > LOG_LEVEL_DEBUG
// 		current_time_g += 4;
// 	#endif 

// 	res = __run_timer(cpu, tq, &time_wheel_bkt_map);
// 	xdp_assert_eq(0, res, "failed run timer");
// 	log_debug("current clk  %lu", tq->clk);
// 	return 0;

// xdp_error:;
// 	return 1;
// }