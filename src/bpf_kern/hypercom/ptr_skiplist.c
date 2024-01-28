/*pointer structure lib-new*/
#include "../common.h"
#include "../bpf_experimental.h"

char _license[] SEC("license") = "GPL";

struct ____node_256 {
	char data[256];
};
typedef struct ____node_256 ptr_node; 

struct ptr_node_container {
	struct list_head node_list;
};

struct ptr_node_container*  ptr_create_node_container(u32 tmp_num) __ksym;
void ptr_destory_node_container(struct ptr_node_container *c)__ksym;
ptr_node* ptr_alloc_node(u32 in_num, u32 out_num)__ksym;
void ptr_release_node(ptr_node *node) __ksym;
ptr_node* ptr_get_out(ptr_node *parent, u32 idx) __ksym;
int ptr_connect(ptr_node *p1, u32 idx1, ptr_node *p2, u32 idx2)  __ksym;
int ptr_unconnect(ptr_node *p1, u32 idx1, ptr_node *p2, u32 idx2) __ksym;
int ptr_write(ptr_node *node, size_t off, void *data__buf, size_t size__sz)__ksym;
void ptr_set_owner(struct ptr_node_container *c, ptr_node *node) __ksym;
void ptr_unset_owner(ptr_node *node) __ksym;
void ptr_container_set_tmp(struct ptr_node_container* c, ptr_node *node, u32 idx) __ksym;
ptr_node*  ptr_container_get_tmp(struct ptr_node_container* c, u32 idx) __ksym;

struct value_type {
        struct ptr_node_container __kptr *container;   
        u32 cnt;
        int init;
};

typedef u64 sl_key_type;
typedef u64 sl_value_type;

struct skip_node {
	u32 in_num; 
	u32 out_num;
	int refcnt;
	u32 data_off;
	struct ptr_node_container *owner; 
	unsigned long in_map;
	unsigned long out_map;
	struct list_head node;
        void *outs[10];
        void *ins[10];
        int height;
        sl_key_type key;
        sl_value_type val;
};

#define MAX_SKIPLIST_HEIGHT 10

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct value_type);  
	__uint(max_entries, 1);
} mymap SEC(".maps");


static __always_inline struct ptr_node_container *container_get_or_create(struct value_type *val)
{
        struct ptr_node_container *sl = bpf_kptr_xchg(&val->container, NULL);
        if (likely(sl != NULL)) {
                log_debug("container_get_or_init get container");
                return sl;
        }
        return ptr_create_node_container(MAX_SKIPLIST_HEIGHT + 2);
}

static __always_inline ptr_node* head_get_or_init(struct ptr_node_container *sl)
{
        ptr_node *head = ptr_container_get_tmp(sl, 0);
        if (likely(head != NULL)) {
                log_debug("sl_head_get_or_init get head");
                return head; 
        }
        head = ptr_alloc_node(MAX_SKIPLIST_HEIGHT, MAX_SKIPLIST_HEIGHT);
        if (unlikely(head == NULL)) {
                log_error("failed to alloc head");
                return NULL;
        }
        /*init head*/
        int max_height = MAX_SKIPLIST_HEIGHT;
        int res = ptr_write(head, offsetof(struct skip_node, height), &max_height, sizeof(max_height));
        if (unlikely(res < 0)) {
                log_error("init failed to write max_height");
                ptr_release_node(head);
                return NULL;
        }
        ptr_set_owner(sl, head);
        ptr_container_set_tmp(sl, head, 0);
        return head;
}

struct __sl_lookup_ctx {
	int current_level;
        struct ptr_node_container *ctx;
        int res; 
        sl_key_type key;
};

#define NOT_FOUND 1;

static int __sl_lookup_loop_bdy(u32 index, void *ctx) {
        struct __sl_lookup_ctx *__ctx = (struct __sl_lookup_ctx*)ctx;
        int current_level = __ctx->current_level;
        if (current_level < 0) {
                log_debug("loop, index %d, level < 0 notfound");
                __ctx->res = NOT_FOUND; /*not found and ctx is the node.key < __ctx -> key*/
                return 1;
        }
        ptr_node *curr = ptr_container_get_tmp(__ctx->ctx, 1);
        if (curr == NULL) {
                log_error("loop, index %d, current_level %d, curr is NULL", index, current_level);
                __ctx->res = -1;  /*error*/
                return 1;
        }
        /*tmp[0] for curr*/
        ptr_container_set_tmp(__ctx->ctx, curr, current_level + 2);
        ptr_node *next = ptr_get_out(curr, current_level);
        if (next == NULL) {
                /*stop search in this level*/
                log_debug("loop, index %d, stop seach in level %d continue next level", index, current_level);
                __ctx->current_level -= 1;
                ptr_release_node(curr);
                return 0;
        }
        struct skip_node *__next = (struct skip_node *)next; 
        if (__next->key == __ctx->key) {
                log_debug("loop, index %d, at level %d key found", index, current_level);
                __ctx->res = 0;
                ptr_container_set_tmp(__ctx->ctx, next, 1);  /*store the results*/
                ptr_release_node(curr);
                ptr_release_node(next);
                return 1;
        } else if (__next->key > __ctx->key) {
                /*down a level*/
                log_debug("loop, index %d, at level %d down a level, __next_key %lu, ctx key %lu", index, current_level, __next->key, __ctx->key);
                __ctx->current_level -= 1;
                ptr_release_node(curr);
                ptr_release_node(next);
                return 0;
        } else {
                log_debug("loop, index %d, at level %d  key search this level, __next_key %lu, ctx key %lu", index, current_level, __next->key, __ctx->key);
                /*continue search*/
                ptr_container_set_tmp(__ctx->ctx, next, 1); 
                ptr_release_node(curr);
                ptr_release_node(next);
                return 0;
        }
}

static __always_inline int sl_get(struct ptr_node_container *sl, ptr_node* head, sl_key_type key, u32* cnt) 
{
        int res; 
        struct skip_node *__head = (struct skip_node*)head;
        struct __sl_lookup_ctx loop_ctx = {
                .current_level = __head->height - 1,
                .ctx = sl,
                .res = -1,
                .key = key,
        };
        ptr_container_set_tmp(sl, head, 1);
        res = bpf_loop(*cnt +  2 * MAX_SKIPLIST_HEIGHT, &__sl_lookup_loop_bdy, &loop_ctx, 0);
        if (res < 0) {
                log_error("bpf_loop fail");
        }
        return loop_ctx.res; 
}

#define RAND_THS (1U << 31)

static __always_inline int grand (int max) {
        int result = 1;
        for (int i = 0; i < MAX_SKIPLIST_HEIGHT; i++) {
                if (bpf_get_prandom_u32() > RAND_THS) {
                        ++result;
                }
        }
        log_debug("grand result %u", result);
        return result;
}

static int sl_enqueue(struct ptr_node_container *sl, ptr_node* head, sl_key_type key, sl_value_type val, u32 *cnt)
{
        int res; 
        struct skip_node *__head = (struct skip_node*)head;
        struct __sl_lookup_ctx loop_ctx = {
                .current_level = __head->height - 1,
                .ctx = sl,
                .res = -1,
                .key = key,
        };
        ptr_container_set_tmp(sl, head, 1);
        res = bpf_loop(*cnt + 2 * MAX_SKIPLIST_HEIGHT, &__sl_lookup_loop_bdy, &loop_ctx, 0);
        if (res < 0) {
                log_error("bpf_loop fail");
                return -1;
        }
        /*find the first one <= node*/
        ptr_node *newentry = ptr_alloc_node(MAX_SKIPLIST_HEIGHT, MAX_SKIPLIST_HEIGHT);
        if (newentry == NULL) {
                log_error("enqueue failed to alloc new node");
                return -1;
        }
        int height = grand(MAX_SKIPLIST_HEIGHT);
        ptr_write(newentry, offsetof(struct skip_node, height), &height, sizeof(height));
        ptr_write(newentry, offsetof(struct skip_node, key), &key, sizeof(key));
        ptr_write(newentry, offsetof(struct skip_node, val), &val, sizeof(val));
        /*set owner*/
        ptr_set_owner(sl, newentry);
        int i; 
        for (i = 0; i < height &&i < MAX_SKIPLIST_HEIGHT; i++) {
                /*disconnect node*/
                ptr_node *pre = ptr_container_get_tmp(sl, i + 2);
                log_debug("connect node pre %p, head %p, level %d", pre, head, i);
                if (pre == NULL) {
                        log_error("pre in height %d is NULL should not happen", i);
                        ptr_unset_owner(newentry);
                        ptr_release_node(newentry);
                        return -1; 
                }
                ptr_node *next = ptr_get_out(pre, i);
                if (next != NULL) {
                        ptr_unconnect(pre, i, next, i);
                        /* new_entry->next[i] =  prev[i]->next[i]*/
                        ptr_connect(newentry, i, next, i);
                        ptr_release_node(next);
                } 
                /*prev[i]->next[i] = newentry*/
                ptr_connect(pre, i, newentry, i);
                ptr_release_node(pre);
                
        }
        ptr_release_node(newentry);
        (*cnt)++;
        return 0;
}

static int sl_dequeue(struct ptr_node_container *sl, ptr_node* head, sl_value_type *val, u32 *cnt) 
{
        ptr_node *next = ptr_get_out(head, 0);
        if (next == NULL) {
                log_debug("empty queue");
                return -1;
        }
        struct skip_node * __next = (struct skip_node *)next;
        struct skip_node * __head = (struct skip_node *)head;
        int height_next = __next->height;
        for (int i = 0; i <  MAX_SKIPLIST_HEIGHT; i++) {
                if (i >= height_next) 
                        break;
                ptr_node *nnext = ptr_get_out(next, i);
                if (nnext == NULL) {
                        ptr_unconnect(head, i, next, i);
                } else {
                        ptr_unconnect(head, i, next, i);
                        ptr_unconnect(next, i, nnext, i);
                        ptr_connect(head, i, nnext, i);
                        ptr_release_node(nnext);
                }
        }
        log_debug("destory node");
        *val = __next->val;
        ptr_unset_owner(next);
        ptr_release_node(next);
        (*cnt)--;
        return 0;
}

SEC("xdp")
int test_skip_list1(struct xdp_md *ctx) 
{
        int key = 0; 
        int res;
        struct value_type *mval;
        mval = bpf_map_lookup_elem(&mymap, &key);
        xdp_assert_neq(NULL, mval, "map lookup failed");
        struct ptr_node_container *sl = container_get_or_create(mval);
        xdp_assert_neq(NULL, sl, "failed to get sl");
        ptr_node *head = head_get_or_init(sl);
        xdp_assert_neq_tag(NULL, head, "faild to get head", drop_sl);
        sl_key_type k = 1;
        sl_value_type v = 2, test_v = 0;
        //enqueue
        res = sl_enqueue(sl, head, k, v, &mval->cnt);
        xdp_assert_eq_tag(0, res, "failed enqueue", drop_head);
        res = sl_dequeue(sl, head, &test_v, &mval->cnt);
        xdp_assert_eq_tag(0, res, "failed dequeue", drop_head);
        xdp_assert_eq_tag(v, test_v, "dequeue result incorrect", drop_head);

        log_info("test success");
        ptr_release_node(head);
        struct ptr_node_container * oldsl = bpf_kptr_xchg(&mval->container, sl);
        if (unlikely(oldsl != NULL)) {
              ptr_destory_node_container(oldsl);  
        }
        log_info("test1 success");
        return XDP_PASS;

drop_head:
        ptr_release_node(head);
drop_sl:
        ptr_destory_node_container(sl);
xdp_error:
        return XDP_DROP;
}


SEC("xdp")
int test_skip_list2(struct xdp_md *ctx) 
{
        int key = 0; 
        int res;
        struct value_type *mval;
        mval = bpf_map_lookup_elem(&mymap, &key);
        xdp_assert_neq(NULL, mval, "map lookup failed");
        struct ptr_node_container *sl = container_get_or_create(mval);
        xdp_assert_neq(NULL, sl, "failed to get sl");
        ptr_node *head = head_get_or_init(sl);
        xdp_assert_neq_tag(NULL, head, "faild to get head", drop_sl);

        //enqueue
        for (int i = 0; i <= 100; i++) {
                log_debug("try to enqueue %d", i);
                sl_key_type k = i;
                sl_value_type v = i;
                res = sl_enqueue(sl, head, k, v, &mval->cnt);
                xdp_assert_eq_tag(0, res, "failed enqueue", drop_head);
        }
        //lookup
        sl_key_type k_to_be_found = 10;
        res = sl_get(sl, head, k_to_be_found, &mval->cnt);
        xdp_assert_eq_tag(0, res, "not found", drop_head); /*found*/

        ptr_node *found = ptr_container_get_tmp(sl, 1);
        xdp_assert_neq_tag(NULL, found, "found should not be NULL", drop_head);
        struct skip_node *__found = (struct skip_node*)(found);
        sl_value_type v_found = __found->val;
        ptr_release_node(found);
        xdp_assert_eq_tag(k_to_be_found, v_found, "found value is not correct", drop_head); /*found*/

        ptr_release_node(head);
        struct ptr_node_container * oldsl = bpf_kptr_xchg(&mval->container, sl);
        if (unlikely(oldsl != NULL)) {
              ptr_destory_node_container(oldsl);  
        }
        log_info("test2 success");
        return XDP_PASS;
drop_head:
        ptr_release_node(head);
drop_sl:
        ptr_destory_node_container(sl);
xdp_error:
        return XDP_DROP;
}

#define ELEM_NUM 1024
#define KV 512

struct __sl_init_loop_ctx {
        struct ptr_node_container *sl;
        ptr_node *head;
        u32 *cnt;
        int res;
};

#define NOT_FOUND 1;

static int __sl_init_loop_body(u32 index, void *ctx) {
        struct __sl_init_loop_ctx  *__ctx = (struct __sl_init_loop_ctx*)ctx;
        sl_key_type k = index;
        sl_value_type v = index;
        int res;
        res = sl_enqueue(__ctx->sl, __ctx->head, k, v, __ctx->cnt);
        if (res < 0) {
                __ctx->res = res;
                return 1;
        } else {
                __ctx->res  = 0;
                return 0;
        }
}



static __always_inline int init_skiplist( struct ptr_node_container *sl, ptr_node *head, u32 *cnt) {
        struct __sl_init_loop_ctx __ctx = {
                .sl = sl,
                .head = head,
                .cnt = cnt,
                .res = 0
        };
        int res;
        res = bpf_loop(ELEM_NUM, &__sl_init_loop_body, &__ctx, 0);
        if (res < 0) goto xdp_error;
        xdp_assert_eq(0, __ctx.res, "sl init failed");
        return 0;
xdp_error:;
        return -1;
}

SEC("xdp")
int xdp_main_lookup(struct xdp_md *ctx) {
        int key = 0; 
        int res;
        struct value_type *mval;
        mval = bpf_map_lookup_elem(&mymap, &key);
        xdp_assert_neq(NULL, mval, "map lookup failed");
        struct ptr_node_container *sl = container_get_or_create(mval);
        xdp_assert_neq(NULL, sl, "failed to get sl");
        ptr_node *head = head_get_or_init(sl);
        xdp_assert_neq_tag(NULL, head, "faild to get head", drop_sl);

        if (unlikely(!mval->init)) {
                res = init_skiplist(sl, head, &mval->cnt);
                xdp_assert_eq_tag(0, res, "init skiplist failed", drop_head); /*found*/
                mval->init = true;
        }
        /*testing*/
        sl_key_type k = KV;
        sl_value_type v = KV;
        sl_value_type res_v;
        res = sl_get(sl, head, k, &mval->cnt);
        xdp_assert_eq_tag(0, res, "not found", drop_head); /*found*/

        ptr_release_node(head);
        struct ptr_node_container * oldsl = bpf_kptr_xchg(&mval->container, sl);
        if (unlikely(oldsl != NULL)) {
              ptr_destory_node_container(oldsl);  
        }
        return XDP_PASS;
drop_head:
        ptr_release_node(head);
drop_sl:
        ptr_destory_node_container(sl);
xdp_error:
        return XDP_DROP;
}