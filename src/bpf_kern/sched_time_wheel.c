#include "common.h"
#include "vmlinux.h"
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

/********************************************/
/**************TW defines********************
**********************************************/

/*TW implementation from linux 2.6.11*/

#define TVN_BITS 6
#define TVR_BITS 8
#define TVN_SIZE (1 << TVN_BITS)
#define TVR_SIZE (1 << TVR_BITS)
#define TVN_MASK (TVN_SIZE - 1)
#define TVR_MASK (TVR_SIZE - 1)
#define TIMER_MAX_LOOKS 20
#define CPU_NUM 40

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


#define BKT_NUM_PER_CPU (TVR_SIZE)

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

static __always_inline unsigned long get_current_time() {
        //return (unsigned long)bpf_jiffies64();
        //current per 1024ns is one tick
        return (unsigned long)bpf_ktime_get_ns() >> 10;
}

static int add_timer_on(__u32 cpu, struct time_wheel_queue *base, void *timer_bkt_map, unsigned long expires) {
	unsigned long idx = expires - base->clk;
        struct time_wheel_bkt_list *tl; 
	int i, key, res;

        if (idx < TVR_SIZE) {
                i = expires & TVR_MASK;
        } else {
                expires = base->clk + (TVR_SIZE - 1);
                i = expires & TVR_MASK;
        }

	key = cpu * BKT_NUM_PER_CPU + i;
	tl = bpf_map_lookup_elem(timer_bkt_map, &key);
	if (tl == NULL) {
		log_error("internal_add_timer failed to lookup timer_bkt_map with key %d", key);
		return -1;
	}

	struct bpf_time_list *elem;
	elem = bpf_obj_new(typeof(*elem));
	if (elem == NULL) {
		log_error("failed to bpf_obj_new(elem)");
		return -2;
	}
	elem->expires = expires;
	bpf_spin_lock(&tl->lock);
	res = bpf_list_push_back(&tl->head, &elem->node);
	bpf_spin_unlock(&tl->lock);

	if (res < 0) {
		log_error("failed to push list back res: %d", res);
		return res; 
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
static int __run_timerlist(u32 index, void *ctx) {
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

static int __run_timer(__u32 cpu, struct time_wheel_queue *base, void *timer_bkt_map) {

        unsigned long current_time = get_current_time();
        int __i, res; 
	log_debug("__run_timer current time %lu", current_time);
        for (__i = 0; __i < TIMER_MAX_LOOKS; __i++) {
                if (time_before(current_time, base->clk)) {
                        break;
                }
                struct time_wheel_bkt_list *tl;
                int index = base->clk  & TVR_MASK;  /*current timer bkt idx*/\
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
                res = bpf_loop(base->cnt, &__run_timerlist, &ctx, 0);
                if (res < 0) {
                        log_error(" failed to run bpf_loop");
                        return res; 
                }
		base->clk += 1;
                log_debug("bpf_loop clk index %d run %d times", index, res);
        }
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

SEC("tc")
int test_timewheel(void *ctx)
{
	int key = 0, res;
	__u32 cpu = bpf_get_smp_processor_id();
	unsigned long ct = get_current_time();
	struct time_wheel_queue *tq;
	tq = bpf_map_lookup_elem(&time_wheel_map, &key);
	xdp_assert_neq(NULL, tq, "failed to lookup time_wheel_map");

	if (!tq->init) {
		log_debug("init current time %lu", ct);
		tq->cnt = 0;
		tq->clk = ct;
		tq->init = 1;
	}

	unsigned long expires = ct + 3;
	res = add_timer_on(cpu, tq, &time_wheel_bkt_map, expires);
	xdp_assert_eq(0, res, "failed add timer");
	
	log_info("wait timer...");

	res = __run_timer(cpu, tq, &time_wheel_bkt_map);
	xdp_assert_eq(0, res, "failed run timer");
	return 0;

xdp_error:;
	return 1;
}