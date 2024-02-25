#include "../common.h"
#include "../bpf_experimental.h"

char _license[] SEC("license") = "GPL";

struct node_2_16_data {
	char data[16];
};

struct local_data {
	char data[16];
};

u32 test_func(u32 data) __ksym;
struct node_2_16_data* node_2_16_new(void) __ksym;
struct node_2_16_data* node_2_16_get_child(struct node_2_16_data *parent, u32 idx) __ksym;
int node_2_16_child_equal(struct node_2_16_data *parent, int idx, struct node_2_16_data *child) __ksym;
int node_2_16_childs_equal(struct node_2_16_data *p1, int idx1, struct node_2_16_data *p2, int idx2) __ksym;
int node_2_16_set_onwer(struct node_2_16_data *parent, struct node_2_16_data *child, u32 idx) __ksym;
struct node_2_16_data* node_2_16_release_child(struct node_2_16_data *parent, u32 idx) __ksym; 
void node_2_16_release(struct node_2_16_data* p) __ksym; 
int node_2_16_write(struct node_2_16_data *parent, size_t off, void *data, size_t size__k) __ksym;

struct value_type {
        struct node_2_16_data __kptr *head;   
};


struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct value_type);  
	__uint(max_entries, 1);
} mymap SEC(".maps");

SEC("xdp")
int test_structure_ptr_write(struct xdp_md *ctx) 
{
        int key = 0; 
        struct value_type *mval;
       
        mval = bpf_map_lookup_elem(&mymap, &key);
        xdp_assert_neq(NULL, mval, "map lookup failed");
        struct node_2_16_data  *node1,  *node2,  *node3; 
        // node1 = bpf_obj_new(typeof(*node1));
        // if (node1 == NULL) goto xdp_error;
        // node1->data[0]= 1;
        // node2 = bpf_kptr_xchg(&mval->head, node1);
        // if (node2 != NULL)
        //  bpf_obj_drop(node2);
        // return XDP_PASS;
        node1 = node_2_16_new();
        if (node1 == NULL) {
                log_error("new node1 failed");
                goto xdp_error;
        }
        node2 = node_2_16_new();
        if (node2 == NULL) {
                log_error("new node2 failed");
                node_2_16_release(node1);
                goto xdp_error;
        }
        node3 = node_2_16_new();
        if (node3 == NULL) {
                log_error("new node3 failed");
                node_2_16_release(node1);
                node_2_16_release(node2);
                goto xdp_error;
        }
        u32 data1 = 1, data2 = 2, data3 = 3;
        node_2_16_write(node1, 0, &data1, 4);
        node_2_16_write(node2, 0, &data2, 4);
        node_2_16_write(node3, 0, &data3, 4);
        // *(u32*)&(node1->data[0]) = 1;
        // *(u32*)&(node2->data[0]) = 2;
        // *(u32*)&(node3->data[0]) = 3;
        int res = node_2_16_set_onwer(node2, node3, 0);
        node_2_16_release(node3);
        if (res < 0) {
                log_error("node_2_16_set_onwer node2->node3 failed");
                node_2_16_release(node1);
                node_2_16_release(node2);
                goto xdp_error;
        }
        node_2_16_set_onwer(node1, node2, 0);
        node_2_16_release(node2);
        if (res < 0) {
                log_error("node_2_16_set_onwer node1->node2 failed");
                node_2_16_release(node1);
                goto xdp_error;
        }
        struct node_2_16_data *old = bpf_kptr_xchg(&mval->head, node1);
        if (old != NULL) {
                 node_2_16_release(old);
        }
        return XDP_PASS;

xdp_error:;
        return XDP_DROP;
}


SEC("xdp")
int test_structure_op(struct xdp_md *ctx) 
{
        int key = 0; 
        struct value_type *mval;
        struct node_2_16_data *old;
        mval = bpf_map_lookup_elem(&mymap, &key);
        xdp_assert_neq(NULL, mval, "map lookup failed");
        struct node_2_16_data *head = bpf_kptr_xchg(&mval->head, NULL);
        xdp_assert_neq(NULL, head, "map head is NULL");

        struct node_2_16_data *node2, *node3;

        node2 = node_2_16_get_child(head, 0);
        xdp_assert_neq_tag(NULL, node2, "node_2_16_get_child node2 failed", put_head);

        node3 = node_2_16_release_child(node2, 0);
        xdp_assert_neq_tag(NULL, node3, "node_2_16_releaes_child node3 failed", put_node2);
        
        int res = node_2_16_set_onwer(head, node3, 1);
        xdp_assert_eq_tag(0, res, "node_2_16_set_onwer head->node3 failed", destroy_node3);

        node_2_16_release(node3);
        node_2_16_release(node2);
        old = bpf_kptr_xchg(&mval->head, head);
        if (old != NULL) {
                 node_2_16_release(old);
        }
        return XDP_PASS;

destroy_node3:;
        node_2_16_release(node3);
put_node2:;
        node_2_16_release(node2);
put_head:;
        old = bpf_kptr_xchg(&mval->head, head);
        if (old != NULL) {
                 node_2_16_release(old);
        }
xdp_error:;
        return XDP_DROP;
}

SEC("xdp")
int test_structure_read(struct xdp_md *ctx) 
{
        int key = 0; 
        struct value_type *mval;
        struct node_2_16_data *old;
        mval = bpf_map_lookup_elem(&mymap, &key);
        xdp_assert_neq(NULL, mval, "map lookup failed");
        struct node_2_16_data *head = bpf_kptr_xchg(&mval->head, NULL);
        xdp_assert_neq(NULL, head, "map head is NULL");

        log_debug("node1: %u", *(u32*)head);
        xdp_assert_eq_tag(1, *(u32*)head, "node1 is not 1", put_head);

        struct node_2_16_data *node2, *node3;
        node2 = node_2_16_get_child(head, 0);
        xdp_assert_neq_tag(NULL, node2, "node_2_16_get_child node2 failed", put_head);
        log_debug("node2: %u", *(u32*)node2);
        xdp_assert_eq_tag(2, *(u32*)node2, "node2 is not 2", put_node2);

        node3 = node_2_16_get_child(head, 1);
        xdp_assert_neq_tag(NULL, node3, "node_2_16_get_child node2 failed", put_node2);
        log_debug("node3: %u", *(u32*)node3);
        xdp_assert_eq_tag(3, *(u32*)node3, "node3 is not 3", put_node3);
        
        node_2_16_release(node3);
        node_2_16_release(node2);
        old = bpf_kptr_xchg(&mval->head, head);
        if (old != NULL) {
                 node_2_16_release(old);
        }
        return XDP_PASS;

put_node3:;
        node_2_16_release(node3);
put_node2:;
        node_2_16_release(node2);
put_head:;
        old = bpf_kptr_xchg(&mval->head, head);
        if (old != NULL) {
                 node_2_16_release(old);
        }

xdp_error:;
        return XDP_DROP;
}
