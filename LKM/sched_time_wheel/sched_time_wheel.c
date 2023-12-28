#include "linux/compiler_attributes.h"
#include "linux/cpumask.h"
#include "linux/list.h"
#include "linux/numa.h"
#include "linux/percpu-defs.h"
#include "linux/percpu.h"
#include <linux/init.h> 
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/bpf.h>
#include <linux/bitops.h>
#include <linux/types.h>

extern int bpf_register_static_cmap(struct bpf_map_ops *map, struct module *onwer);
extern void bpf_unregister_static_cmap(struct module *onwer);
extern void bpf_map_area_free(void *area);
extern void *bpf_map_area_alloc(u64 size, int numa_node);

#define TIME_SHIFT 13

#define TVN_BITS 6
#define TVR_BITS 8

#define TVN_SIZE (1 << TVN_BITS)
#define TVR_SIZE (1 << TVR_BITS)
#define TVN_MASK (TVN_SIZE - 1)
#define TVR_MASK (TVR_SIZE - 1)

typedef struct __tvec_s {
	struct list_head vec[TVN_SIZE];
} __tvec_t;

typedef struct __tvec_root_s {
	struct list_head vec[TVR_SIZE];
} __tvec_root_t;

/*resources: list of tv1 (all entries in list) and list of tv2  (all entries in list)*/
struct cascade_time_wheel {
        unsigned long clk;
        __tvec_root_t tv1;  /*vec of list should be freed in map free */
	__tvec_t tv2;   /*vec of list should be freed in map free */
} ____cacheline_aligned_in_smp;

struct time_wheel_map {
        struct bpf_map map;
        struct cascade_time_wheel __percpu *tw;
};

struct __tw_value_type {
        unsigned long expires;
};

struct __timer_list {
        struct list_head entry;
        unsigned long expires;
};

// extern int bpf_register_custom_map(struct bpf_custom_map_ops *cmap);
// extern void bpf_unregister_custom_map(struct bpf_custom_map_ops *cmap);

static __always_inline unsigned long get_current_time(void) 
{
        return (unsigned long)(ktime_get_mono_fast_ns() >> TIME_SHIFT);
}

int tw_alloc_check(union bpf_attr *attr) {
	if (attr->key_size != 4 
                || attr->value_size != sizeof(struct __tw_value_type)
                || attr->max_entries != (TVN_SIZE + TVR_SIZE)) {
                return -EINVAL;
        }
        return 0;
}

/*
*@return 0 means success
*/

static __always_inline void __init_timer_list(struct cascade_time_wheel *tw) 
{
        int i;
        for (i = 0; i < TVR_SIZE; i++) {
                INIT_LIST_HEAD(tw->tv1.vec + i);
        }     
        for (i = 0; i < TVN_SIZE; i++) {
                INIT_LIST_HEAD(tw->tv2.vec + i);
        }        
}

static __always_inline void __free_timer_list(struct cascade_time_wheel *tw) 
{
        int i;
        struct __timer_list *timer, *n;
        for (i = 0; i < TVR_SIZE; i++) {
                list_for_each_entry_safe(timer, n, tw->tv1.vec + i , entry) {
                        /* timer is allocated in update elem, free here*/
                        list_del(&timer->entry);
                        bpf_map_area_free(timer);
                }
        }     
        for (i = 0; i < TVN_SIZE; i++) {
                list_for_each_entry_safe(timer, n, tw->tv2.vec + i , entry) {
                        /* timer is allocated in update elem, free here*/
                        list_del(&timer->entry);
                        bpf_map_area_free(timer);
                }
        }      
}

static struct bpf_map *tw_alloc(union bpf_attr *attr)
{
        struct time_wheel_map *tmap;
        void *res_ptr; 
        int cpu;
        
        tmap = bpf_map_area_alloc(sizeof(struct time_wheel_map), NUMA_NO_NODE);
        if (tmap == NULL) {
                return ERR_PTR(-ENOMEM);
        }
        tmap->tw = __alloc_percpu_gfp(sizeof(struct cascade_time_wheel), __alignof__(u64), GFP_USER | __GFP_NOWARN);
        if (tmap->tw == NULL) {
                res_ptr = ERR_PTR(-ENOMEM);
                goto free_tmap;
        }
        for_each_possible_cpu(cpu) {
                struct cascade_time_wheel *__tw;
                unsigned long ct;   /*current time*/
                __tw = per_cpu_ptr(tmap->tw, cpu);
                __init_timer_list(__tw);
                ct = get_current_time();
                __tw->clk = ct;
        }

	return (struct bpf_map*)tmap;
free_tmap:;
        return res_ptr;
}

static void tw_free(struct bpf_map *map) {
        struct time_wheel_map *tmap = container_of(map, struct time_wheel_map, map);
        __free_timer_list(tmap->tw);
        free_percpu(tmap->tw);
        bpf_map_area_free(tmap);
        return;
}

static void internal_add_timer(struct cascade_time_wheel *tw, struct __timer_list *timer)
{
	unsigned long expires = timer->expires;
	unsigned long idx = expires - tw->clk;
	struct list_head *vec;

	if (idx < TVR_SIZE) {
		int i = expires & TVR_MASK;
		vec = tw->tv1.vec + i;
	} else if (idx < 1 << (TVR_BITS + TVN_BITS)) {
		int i = (expires >> TVR_BITS) & TVN_MASK;
		vec = tw->tv2.vec + i;
	} else if ((signed long) idx < 0) {
		/*
		 * Can happen if you add a timer with expires == jiffies,
		 * or you set a timer to go off in the past
		 */
		vec = tw->tv1.vec + (tw->clk & TVR_MASK);
                pr_warn("idx < 0 add timer to current clk");
	} else {
                expires = tw->clk + (1 << (TVR_BITS + TVN_BITS)) - 1;
                int i = ((expires >> TVR_BITS) & TVN_MASK);
		vec = tw->tv2.vec + i;
                pr_warn("add timer to lv2(max) index %d", i);
	}
	/*
	 * Timers are FIFO:
	 */
	list_add_tail(&timer->entry, vec);
}

/*enqueue elem*/
static long tw_push_elem(struct bpf_map *map, void *value, u64 flags)
{
        struct time_wheel_map *tmap = container_of(map, struct time_wheel_map, map);
        struct __tw_value_type *__value = (struct __tw_value_type *)value; 
        struct __timer_list *timer; 
        struct cascade_time_wheel *tw;

        /* alloc __timer_list, free in map_free or pop_elem/run_timer*/
        timer = bpf_map_area_alloc(sizeof(*timer), NUMA_NO_NODE);
        if (timer == NULL) {
                /*failed to alloc timer*/
                return -ENOMEM;
        }
        timer->expires = __value->expires;
        tw = this_cpu_ptr(tmap->tw);
        internal_add_timer(tw, timer);
        return 0;
}

static int __cascade(struct cascade_time_wheel *tw, __tvec_t *tv, int index)
{
	/* cascade all the timers from tv up one level */
	struct list_head *head, *curr;

	head = tv->vec + index;
	curr = head->next;
	/*
	 * We are removing _all_ timers from the list, so we don't  have to
	 * detach them individually, just clear the list afterwards.
	 */
	while (curr != head) {
		struct __timer_list *tmp;
		tmp = list_entry(curr, struct __timer_list, entry);
		curr = curr->next;
		internal_add_timer(tw, tmp);
	}
	INIT_LIST_HEAD(head);
	return index;
}


#define INDEX(N) (tw->clk >> (TVR_BITS + N * TVN_BITS)) & TVN_MASK

static void __run_timers(struct cascade_time_wheel *tw, u64 *cnt)
{
	struct __timer_list *timer;
        unsigned long current_time = get_current_time();
        *cnt = 0;
        pr_debug("__run_timer current time %lu", current_time);
	while (time_after_eq(current_time, tw->clk)) {
		struct list_head work_list = LIST_HEAD_INIT(work_list);
		struct list_head *head = &work_list;
 		int index = tw->clk & TVR_MASK;
 
		/*
		 * Cascade timers:
		 */
                /* if (!index &&
		 * 	(!cascade(base, &base->tv2, INDEX(0))) &&
		 *		(!cascade(base, &base->tv3, INDEX(1))) &&
	         * 			!cascade(base, &base->tv4, INDEX(2)))
		 *	cascade(base, &base->tv5, INDEX(3));
                 */
                if (!index) {
			__cascade(tw, &tw->tv2, INDEX(0));
		}	
		
		++tw->clk; 
		list_splice_init(tw->tv1.vec + index, &work_list);
repeat:
		if (!list_empty(head)) {
                        /*simple pop and add value*/
			timer = list_entry(head->next, struct __timer_list, entry);
                
                        /*add user defined eBPF callback here*/
                        pr_debug("timer expires: %lu, current clk %lu", timer->expires, tw->clk);
                        *cnt += 1;
			list_del(&timer->entry);
                        bpf_map_area_free(timer);
			goto repeat;
		}
                pr_debug("__run_timer plus 1 tick, %lu", tw->clk);
	}
}

/*
* current value set the expires timer
* eBPF program call pop_elem to run_timers 
*/
static long tw_pop_elem(struct bpf_map *map, void *value) 
{       
        struct time_wheel_map *tmap = container_of(map, struct time_wheel_map, map);
        struct cascade_time_wheel *tw = this_cpu_ptr(tmap->tw);
        u64 * expire_timers = (u64 *)value;
        __run_timers(tw, expire_timers);
        return 0;
}

static u64 tw_mem_usage(const struct bpf_map *map) 
{
        return sizeof(struct cascade_time_wheel) * num_possible_cpus();
}

static struct bpf_map_ops tw_piq_ops = {
	.map_alloc_check = tw_alloc_check,
	.map_alloc = tw_alloc,
	.map_free = tw_free,
	.map_push_elem = tw_push_elem,
        .map_pop_elem = tw_pop_elem,
	.map_mem_usage = tw_mem_usage
};

//extern int bpf_register_static_cmap(struct bpf_map_ops *map, struct module *onwer);
//extern void bpf_unregister_static_cmap(struct module *onwer);

static int __init static_time_wheel_init(void) {
	pr_info("register static time wheel");
	return bpf_register_static_cmap(&tw_piq_ops, THIS_MODULE);
}

static void __exit static_time_wheel_exit(void) {
	pr_info("unregister static time wheel");
	bpf_unregister_static_cmap(THIS_MODULE);
}

/* Register module functions */
module_init(static_time_wheel_init);
module_exit(static_time_wheel_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chonepieceyb");
MODULE_DESCRIPTION("time wheel LKM implementation");
MODULE_VERSION("0.01");