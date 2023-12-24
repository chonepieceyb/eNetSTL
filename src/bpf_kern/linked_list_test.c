#include "common.h"
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

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
int map_list_push_pop_inmap(void *ctx)
{
	 /* ... in BPF program */
	int key = 0;
	struct map_value *v;
	v = bpf_map_lookup_elem(&array_map, &key);
	if (v == NULL)
		return -1;
	log_info("link list storeed in map");
	return __add_three(&v->head, &v->lock);

}

SEC("tc")
int map_list_push_pop_global(void *ctx)
{
	 /* ... in BPF program */
	int key = 0;
	struct map_value *v;
	v = bpf_map_lookup_elem(&array_map, &key);
	if (v == NULL)
		return -1;
	log_info("link list global");
	return __add_three(&ghead, &glock);

}