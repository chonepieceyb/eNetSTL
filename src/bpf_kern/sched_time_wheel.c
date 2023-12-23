#include "common.h"
#include "vmlinux.h"
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

/********************************************/
/**************TW defines********************
**********************************************/

/*TW implementation from linux 2.6.11*/

// #define TVN_BITS 6
// #define TVR_BITS 8
// #define TVN_SIZE (1 << TVN_BITS)
// #define TVR_SIZE (1 << TVR_BITS)
// #define TVN_MASK (TVN_SIZE - 1)
// #define TVR_MASK (TVR_SIZE - 1)
// #define TIMER_MAX_LOOKS 128

// #define time_after(a,b)		\
// 	(typecheck(unsigned long, a) && \
// 	 typecheck(unsigned long, b) && \
// 	 ((long)(b) - (long)(a) < 0))
// #define time_before(a,b)	time_after(b,a)

// #define time_after_eq(a,b)	\
// 	(typecheck(unsigned long, a) && \
// 	 typecheck(unsigned long, b) && \
// 	 ((long)(a) - (long)(b) >= 0))
// #define time_before_eq(a,b)	time_after_eq(b,a)

// /*elem of the time list*/
// struct bpf_time_list {
//         struct bpf_list_node node; 
//         unsigned long expires;
// };

// struct __tvec_root_t {
// 	//__list_head vec [TVR_SIZE] __contains(bpf_time_list, node);
//         struct bpf_list_head head;
// };

// struct time_wheel_queue {
//         unsigned long clk;
//         struct bpf_list_head head; 
//         __u32 cnt; 
//         int init;
// };

// static __always_inline unsigned long get_current_time() {
//         //return (unsigned long)bpf_jiffies64();
//         //current per 64ns is one tick
//         return (unsigned long)bpf_ktime_get_ns() >> 6;
// }

// static __always_inline int internal_add_timer(struct time_wheel_queue *base, struct bpf_time_list *timer)
// {
// 	// unsigned long expires = timer->expires;
// 	// unsigned long idx = expires - base->clk;
//         // __list_head *vec; 

//         // if (idx < TVR_SIZE) {
//         //         int i = expires & TVR_MASK;
//         //         asm_bound_check(i, 256);
//         //         vec = base->tv1.vec + i;
//         // } else {
//         //         expires = base->clk + (TVR_SIZE - 1);
//         //         int i = expires & TVR_MASK;
//         //         asm_bound_check(i, 256);
//         //         vec = base->tv1.vec + i;
//         // }

//         return bpf_list_push_back(&base->tv1.head, &timer->node);
// }

// static __always_inline int add_timer(struct time_wheel_queue *base, struct bpf_time_list *timer) {
//         return internal_add_timer(base, timer);
// }

// struct __run_timerlist_ctx {
//         __list_head *head; 
// };


// /*impl expires action here*/
// static int __run_timerlist(u32 index, void *ctx) {
//         struct __run_timerlist_ctx *__ctx = (struct __run_timerlist_ctx*)ctx;
//         __list_node *n;
//         struct bpf_time_list *elem;
//         /* pop node from list*/
//         n = bpf_list_pop_front(__ctx->head);
//         if (n == NULL) {
//                 /*skip the loop*/
//                 return 1;
//         }
//         elem = container_of(n, struct bpf_time_list, node);
        
//         /*** get the elem ******/
//         log_debug("pop elem expires %lu", elem->expires);
//         bpf_obj_drop(n);
//         return 0;
// }


// static int __run_timer(struct time_wheel_queue *base) {

//         unsigned long current_time = get_current_time();
//         int __i, res; 
//         for (__i = 0; __i < TIMER_MAX_LOOKS; __i++) {
//                 if (time_before(current_time, base->clk)) {
//                         break;
//                 }
//                 __list_head *work_list; 
//                 int index = base->clk  & TVR_MASK;  /*current timer bkt idx*/
//                 asm_bound_check(index, 256);
//                 work_list = base->tv1.vec + index;
//                 /* travel the work list*/
//                 struct __run_timerlist_ctx ctx;
//                 ctx.head = work_list;
//                 res = bpf_loop(base->cnt, &__run_timerlist, &ctx, 0);
//                 if (res < 0) {
//                         log_error("failed to start bpf_loop");
//                         return res; 
//                 }
//                 log_debug("bpf_loop clk index %d run %d times", index, res);
//         }
//         return 0;
// }

// struct bar {
// 	struct bpf_list_node node;
// 	int data;
// };

// struct __wrapper {
// 	struct bpf_list_head head[4];
// };

// struct map_value {
// 	struct __wrapper w;
// };

// struct array_map {
// 	__uint(type, BPF_MAP_TYPE_ARRAY);
// 	__type(key, int);
// 	__type(value, struct map_value);
// 	__uint(max_entries, 1);
// };

// struct array_map array_map SEC(".maps");


struct node_data {
	long data;
	struct bpf_list_node node;
};

struct map_value {
	struct bpf_list_head head __contains(node_data, node);
	struct bpf_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct map_value);  
	__uint(max_entries, 1);
} array_map SEC(".maps");

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))

private(A) struct bpf_spin_lock glock;
private(A) struct bpf_list_head ghead __contains(node_data, node);

static int __add_three(struct bpf_list_head *head, struct bpf_spin_lock *lock)
{
	struct node_data *n;
	struct bpf_list_node *rn;
	int res;
	n = bpf_obj_new(typeof(*n));
	if (!n)
		return 1;
	n->data = 13;

	bpf_spin_lock(lock);
	res = bpf_list_push_back(head, &n->node);
	bpf_spin_unlock(lock);

	if (res != 0) {
		log_error("res: %d",res);
		return 2;
	}
		

	bpf_spin_lock(lock);
	rn = bpf_list_pop_front(head);
	bpf_spin_unlock(lock);
	if (!rn)
		return 3;
	struct node_data *res_node = container_of(rn, struct node_data, node);
	if (res_node->data != 13) {
		bpf_obj_drop(res_node);
		return 4;
	}
	bpf_obj_drop(res_node);
	log_debug("test success");
	return 0;
}

SEC("tc")
int map_list_push_pop(void *ctx)
{
	 /* ... in BPF program */
	int key = 0;
	struct map_value *v;
	v = bpf_map_lookup_elem(&array_map, &key);
	if (v == NULL)
		return -1;
	log_debug("store in map");
	return __add_three(&v->head, &v->lock);

}