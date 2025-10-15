#include "bpf_static_ptr.h"
#include "bpf_memalloc.h"
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/bitops.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/spinlock.h>

#define MAX_PROXY_NUM 1


static struct bpf_mem_alloc batch_ma;

static struct eNetSTL_node_proxy node_proxys[MAX_PROXY_NUM] = {0};

//HINT: a hole batch avoid runtime safety check, for all allocated batches, for example , for example, if proxy->batches[i] is not allocated, batches[i] = &hole_batch rather that NULL
static struct __node_batch hole_batch;

static void enlarge_capacity_rcu_callback(struct rcu_head *rcu)
{
	struct eNetSTL_node_container *old_container = container_of(rcu, struct eNetSTL_node_container, rcu);
	kfree(old_container);
}

static void destroy_proxy_rcu_callback(struct rcu_head *rcu)
{
	struct eNetSTL_node_container *container = container_of(rcu, struct eNetSTL_node_container, rcu);
	int i;
	int batch_count = container->batches_mask + 1;

	// free all node batches using bpf_mem_cache_free
	for (i = 0; i < batch_count; i++) {
		if (container->batches[i] && container->batches[i] != &hole_batch) {
			preempt_disable();
			bpf_mem_cache_free(&batch_ma, container->batches[i]);
			preempt_enable();
		}
	}

	kfree(container);
}

//should be invoked with KF_SLEEPABLE
struct eNetSTL_node_proxy* enetstl_create_node_proxy(void) {
        struct eNetSTL_node_proxy *proxy;
        int i, slot = -1;
        u64 batch_num = DEFAULT_BATCHES_NUM;
        struct eNetSTL_node_container *container;

        // TODO:
        // 1. try to alloc a new proxy (if there is empty slot) 
        for (i = 0; i < MAX_PROXY_NUM; i++) {
                proxy = &node_proxys[i];
                spin_lock(&proxy->lock);
                if (proxy->fd != -1) {
                        spin_unlock(&proxy->lock);
                        continue; // already used
                } else {
                        slot = i;
                        proxy->fd = i; // mark as used
                        WARN_ONCE(proxy->container != NULL, "proxy container is not NULL when creating new one in a free proxy\n");
                        spin_unlock(&proxy->lock);
                        break;
                }
        }

        if (slot == -1)
                return NULL;

        // 3. when init, alloc batches, alloc batches using kmalloc
        container = kmalloc(sizeof(*container) + sizeof(struct __node_batch*) * batch_num, GFP_KERNEL);
        if (!container) {
                goto alloc_error;
        }

        container->free_list_head = 0;
        container->batches_mask = batch_num - 1;
        container->capacity = (batch_num << NODE_BATCH_SIZE_SHIFT);
        container->fd = proxy->fd;

        // 4. for each batch, alloc struct __node_batches using  bpf_mem_cache_alloc, check LKMs/bpf_ptr_structure_lib.c  and bpf_memalloc.h for example of using bpf_mem_cache_alloc
        for (i = 0; i < batch_num; i++) {
                container->batches[i] = bpf_mem_cache_alloc(&batch_ma);
                if (!container->batches[i]) {
                        // cleanup on failure
                        while (--i >= 0) {
                                bpf_mem_cache_free(&batch_ma, container->batches[i]);
                        }
                        kfree(container);
                        goto alloc_error;
                }
        }
        container->batches_unalloc_idx = batch_num;

        // 5. for all node init next_idx to initialize freelist
        for (i = 0; i < batch_num; i++) {
                u64 j;
                for (j = 0; j < NODE_BATCH_SIZE; j++) {
                        u64 node_idx = (i << NODE_BATCH_SIZE_SHIFT) + j;
                        container->batches[i]->nodes[j].next_idx = node_idx + 1;
                }
        }

        // 6. if init fail, return NULL
        spin_lock(&proxy->lock);
        rcu_assign_pointer(proxy->container, container); //old should be NULL here
        spin_unlock(&proxy->lock);

        // No need for callback since we're not replacing any existing container
        return proxy;

alloc_error:;
        spin_lock(&proxy->lock);
        proxy->fd = -1; // mark as free
        spin_unlock(&proxy->lock);
        return NULL;
}


struct eNetSTL_node_container* enetstl_get_nodes(int fd) {
        //we don't use lock here for performance, we just make sure that container is protected by RCU
        struct eNetSTL_node_proxy *proxy;
        struct eNetSTL_node_container *container;
        proxy = &node_proxys[fd & (MAX_PROXY_NUM - 1)];
        rcu_read_lock();
        //XDP program should be in rcu read side context
        container = rcu_dereference(proxy->container);
        if (!container) {
                rcu_read_unlock();
                return NULL;
        }
        return container;
}

void enetstl_put_nodes(struct eNetSTL_node_container* container) {
        rcu_read_unlock();
}

struct eNetSTL_node* enetstl_alloc_node(struct eNetSTL_node_container* container, u64 *idx) {
        //How to implement a thread-safe version? may be we can use percpu node cache to reduce contention, for testing, we use a simple version without thread-safety concern
        //This function should be reimplement later (use percpu cache + spinlock)
        struct eNetSTL_node *node;
        u64 node_idx, batch_idx;
        u64 current_capacity;

        // 1. alloc a new node from the container, if success, set *idx to the index of the node, set *current_capacity to current capacity of the proxy, return the node pointer
        current_capacity = container->capacity;

        if (container->free_list_head == current_capacity &&
                container->batches_unalloc_idx >= (container->batches_mask + 1)) {
                // if capacity is full, return NULL
                return NULL;
        }
        batch_idx = container->free_list_head >> NODE_BATCH_SIZE_SHIFT;
        WARN_ONCE(batch_idx > container->batches_unalloc_idx, "batch_idx %llu > batches_unalloc_idx %llu\n", batch_idx, container->batches_unalloc_idx);
        if (batch_idx >= container->batches_unalloc_idx) {
                /* the node batch has not been allocated*/
                struct __node_batch *new_batch = bpf_mem_cache_alloc(&batch_ma);
                if (!new_batch)
                        return NULL;
                container->batches[batch_idx] = new_batch;
                container->batches_unalloc_idx++;
                // initialize nodes in new batch and add to free list
                u64 i;
                //container->free_list_head = (batch_idx << NODE_BATCH_SIZE_SHIFT); // point free_list_head to the first node in the new batch
                for (i = 0; i < NODE_BATCH_SIZE; i++) {
                        u64 current_node_idx = (batch_idx << NODE_BATCH_SIZE_SHIFT) + i;  
                        new_batch->nodes[i].next_idx = current_node_idx + 1;
                }
        }
        // allocate node from free list
        node_idx = container->free_list_head;
        node = __get_batch_idx(node_idx, container);
        container->free_list_head = node->next_idx;
        //clear the node to zero
        memset(node, 0, sizeof(*node));
        *idx = node_idx;
        return node;
}

void enetstl_free_node(struct eNetSTL_node_container *container, u64 idx) {

        struct eNetSTL_node *node;
        node = __get_batch_idx(idx, container);
        // add node back to free list
        node->next_idx = container->free_list_head;
        container->free_list_head = idx;
}

/*for enlarge we should release old container first*/
void enetstl_enlarge_capacity(struct eNetSTL_node_container *old_container) {
        struct eNetSTL_node_proxy *proxy;
        struct eNetSTL_node_container *new_container;
        u64 old_batch_num, new_batch_num;
        u64 i;
        proxy = &node_proxys[old_container->fd & (MAX_PROXY_NUM - 1)];
        old_batch_num = READ_ONCE(old_container->batches_mask) + 1;
        rcu_read_unlock();
        
        new_batch_num = old_batch_num * 2;  // double the capacity
        // 1. recreate a eNetSTL_node_proxy with new capacity
        new_container = kmalloc(sizeof(*new_container) + sizeof(struct __node_batch*) * new_batch_num, GFP_KERNEL);
        if (!new_container)
                return;
        // init the new one 
        spin_lock(&proxy->lock);
        old_container = rcu_dereference_protected(proxy->container, lockdep_is_held(&proxy->lock));
        if (!old_container) {
                spin_unlock(&proxy->lock);
                kfree(new_container);
                return;  //invalid fd
        }

        if (old_batch_num != READ_ONCE(old_container->batches_mask) + 1) {
                // the old proxy has been changed, we should not enlarge capacity
                spin_unlock(&proxy->lock);
                kfree(new_container);
                return;
        }

        new_container->free_list_head = old_container->free_list_head;
        new_container->batches_mask = new_batch_num - 1;
        new_container->capacity = (new_batch_num << NODE_BATCH_SIZE_SHIFT);
        new_container->batches_unalloc_idx = old_container->batches_unalloc_idx;
        new_container->fd = proxy->fd;

        // 2. copy old batches to new container (do not allocated struct __node_batches again, just copy the pointer)
        for (i = 0; i < old_batch_num; i++) {
                new_container->batches[i] = old_container->batches[i];
        }

        // 3. for new batches, set the pointer to hole batch, delay the actual allocation to when we need to alloc a node in the batch
        for (i = old_batch_num; i < new_batch_num; i++) {
                new_container->batches[i] = &hole_batch;
        }

        // 4. use rcu to replace the old container with the new one, free the old one (just free the container structure, do not free the struct __node_batches, as they are used by the new container now)
        rcu_assign_pointer(proxy->container, new_container);
        spin_unlock(&proxy->lock);

        // Use call_rcu instead of synchronize_rcu for non-blocking behavior
        call_rcu(&old_container->rcu, enlarge_capacity_rcu_callback);
        return;
}

void enetstl_destroy_node_proxy(struct eNetSTL_node_proxy* proxy) {
        struct eNetSTL_node_container *old_container;

        if (!proxy)
                return;

        spin_lock(&proxy->lock);
        old_container = rcu_dereference_protected(proxy->container, lockdep_is_held(&proxy->lock));
        if (!old_container) {
                spin_unlock(&proxy->lock);
                return;
        }
        rcu_assign_pointer(proxy->container, NULL);
        proxy->fd = -1; // mark as free
        spin_unlock(&proxy->lock);

        // Use call_rcu instead of synchronize_rcu for non-blocking behavior
        call_rcu(&old_container->rcu, destroy_proxy_rcu_callback);
}

//call when the kernel module is loaded
int node_proxys_init(void)
{
        int ret;
        preempt_disable();
        ret = bpf_mem_alloc_init(&batch_ma, sizeof(struct __node_batch), false);
        preempt_enable();
        if (ret) {
                pr_err("batch_ma init fail ret %d", ret);
                return ret;
        }

        // initialize hole_batch
        memset(&hole_batch, 0, sizeof(hole_batch));

        // initialize node_proxys
        for (int i = 0; i < MAX_PROXY_NUM; i++) {
                node_proxys[i].fd = -1;
                node_proxys[i].container = NULL;
                spin_lock_init(&node_proxys[i].lock);
        }

        return 0;
}

void node_proxys_exit(void)
{
        preempt_disable();
        bpf_mem_alloc_destroy(&batch_ma);
        preempt_enable();
}