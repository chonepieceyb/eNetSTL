#include "linux/percpu-defs.h"
#include <linux/bpf_mem_alloc.h>
#include <linux/init.h> 
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/math.h>
#include <linux/bpf.h>

/*binding for RUST*/

void* enetstl_get_this_cpu_data(void *percpu_ptr)
{
        return this_cpu_ptr((void __percpu*)percpu_ptr);
}

void* enetstl_get_cpu_data(void *percpu_ptr, int cpu)
{
        return per_cpu_ptr((void __percpu*)percpu_ptr, cpu);
}

void* enetstl_alloc_percpu(size_t size)
{
        return __alloc_percpu_gfp(sizeof(struct list_head), __alignof__(u64), GFP_USER | __GFP_NOWARN);
}

void enetstl_free_percpu(void *percpu_ptr)
{
        free_percpu((void __percpu*)percpu_ptr);
}

int enetstl_get_next_cpu(int cpu)
{
        if (cpu < 0)
                return -1;
        int bit = find_next_bit(cpumask_bits(cpu_possible_mask), small_cpumask_bits, cpu);
        if (bit >= small_cpumask_bits) {
                return -1;
        }
        return bit;
}