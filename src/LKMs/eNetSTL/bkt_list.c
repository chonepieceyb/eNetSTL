#include "linux/cpumask.h"
#include <linux/bpf_mem_alloc.h>
#include <linux/init.h> 
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/math.h>
#include <linux/bpf.h>
#include "bkt_list.h"


/*RUST implementation*/
extern u64 rust_get_bkt_cache_object_size(void);
extern u64 rust_get_bkt_map_area_size(void);
extern int rust_init_bkt_map(void* map_area);
extern void rust_clear_bkt_map(void *map_area);
extern int rust_pop_front(void *map_area, void *buf, size_t size, size_t slot);
extern int rust_push_back(void *map_area, const void *buf, u32 size, size_t slot);

#define BKT_LIST_SIZE 1

/*cache allocator*/
/*TODO add ioctl to create multiple instance of listbuckets*/
static struct bpf_mem_alloc bucket_ma;
static struct bkt_list list_buckets; 

/*APIs for RUST to invoke, to alloc bpf_mem_cache*/
void* enetstl_bkt_cache_obj_alloc(void)
{
        return  bpf_mem_cache_alloc(&bucket_ma);
}

void enetstl_bkt_cache_obj_free(void *obj)
{
        bpf_mem_cache_free(&bucket_ma, obj);
}

// struct bkt_list* bktlist_new(void)
// {
//         int res; 
//         int * __in_use = this_cpu_ptr(list_buckets.in_use);
//         if (*__in_use == 1)
//                 return NULL;
//         void *map_area = this_cpu_ptr(list_buckets.map_mem);
//         res = rust_init_bkt_map(map_area);
//         if (res < 0)
//                 return NULL;
//         return &list_buckets;
// }       

// void bktlist_free(struct bkt_list *bktlist) 
// {
//         /*clear*/
//         //void *map_area = this_cpu_ptr(bktlist->map_mem);
//         //rust_clear_bkt_map(map_area);
//         int *__in_use = this_cpu_ptr(bktlist->in_use);
//         *__in_use = 0;
// }

// int bktlist_pop_front(struct bkt_list *bktlist, void *buf, size_t size, size_t slot) 
// {
//         void *map_area = this_cpu_ptr(bktlist->map_mem);
//         return rust_pop_front(map_area, buf, size, slot);
// }

// int bktlist_push_back(struct bkt_list *bktlist, const void *buf, size_t size, size_t slot)
// {
//         void *map_area = this_cpu_ptr(bktlist->map_mem);
//         return rust_push_back(map_area, buf, size, slot);
// }


struct bkt_list* bktlist_new(void)
{
        int res; 
        int fd = list_buckets.fd;
        int curr_cpu = 0, cpu = 0;

        if (fd != 0)
                return NULL;

        for_each_possible_cpu(curr_cpu) {
                void *map_area = per_cpu_ptr(list_buckets.map_mem, cpu);
                res = rust_init_bkt_map(map_area);
                if (res < 0)
                        goto clear_bktlist;
        }
        
        list_buckets.fd = 1;  //mark as allocated
        return &list_buckets;

clear_bktlist:;
        //failed to alloc currcpu 
        for (cpu = 0; cpu < curr_cpu; cpu++) {
              void *map_area = per_cpu_ptr(list_buckets.map_mem, cpu);  
              rust_clear_bkt_map(map_area);
        }
        return NULL;
}       

void bktlist_free(struct bkt_list *__list_buckets) 
{
        if (__list_buckets->fd != 1)
                return;
        int cpu = 0;
        for_each_possible_cpu(cpu) {
                void *map_area = per_cpu_ptr(__list_buckets->map_mem, cpu);
                rust_clear_bkt_map(map_area);
        }
        __list_buckets->fd = 0;
}

int bktlist_pop_front(int fd, void *buf, size_t size, size_t slot) 
{
        if (fd != 1) 
                return -1;
        void *map_area = this_cpu_ptr(list_buckets.map_mem);
        return rust_pop_front(map_area, buf, size, slot);
}

int bktlist_push_back(int fd, const void *buf, size_t size, size_t slot)
{
        if (fd != 1) 
                return -1;
        void *map_area = this_cpu_ptr(list_buckets.map_mem);
        return rust_push_back(map_area, buf, size, slot);
}

int init_bktlist_module(void) {
        u32 cache_size;
        u32 map_size;
        int res;
        cache_size = rust_get_bkt_cache_object_size();
        map_size = rust_get_bkt_map_area_size();
        list_buckets.fd = 0;
        list_buckets.map_mem = __alloc_percpu_gfp(map_size, __alignof__(u64), GFP_USER | __GFP_NOWARN);
        if (list_buckets.map_mem == NULL) {
                return -ENOMEM;
        }
        preempt_disable();
        res = bpf_mem_alloc_init(&bucket_ma, cache_size, false);
        preempt_enable();

        if (res != 0) {
		/* alloc mem_alloc_cache*/
                goto free_percpu_map_mem;
	}

        return 0;

free_percpu_map_mem:;
        free_percpu(list_buckets.map_mem);
        return -1;
}

void free_bktlist_module(void) {
        free_percpu(list_buckets.map_mem);
        preempt_disable();
	bpf_mem_alloc_destroy(&bucket_ma);
        preempt_enable();
}