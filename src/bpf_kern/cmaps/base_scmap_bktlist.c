#include "../common.h"


char _license[] SEC("license") = "GPL";

#define FRONT_TAIL_BIT_POS 0     //bit pos, set means front 
#define INS_LOOK_BIT_POS 1     //bit pos, set means insert

#define bktlist_lookup_flag(ins_look, front_tail)			\
({									\
	u32 __flags = 0;						\
	u32 __ins_look = !!(ins_look);					\
	u32 __front_tail = !!(front_tail);				\
	__flags |= (__ins_look << INS_LOOK_BIT_POS);			\
	__flags |= (__front_tail << FRONT_TAIL_BIT_POS);		\
})

#define bktlist_delete_flag(front_tail)				        \
({									\
	u32 __flags = 0;						\
	u32 __front_tail = !!(front_tail);				\
	__flags |= (__front_tail << FRONT_TAIL_BIT_POS);			\
})


#define bktlist_flag_lookup_front  bktlist_lookup_flag(0, 1)
#define bktlist_flag_lookup_tail   bktlist_lookup_flag(0, 0)
#define bktlist_flag_ins_front  bktlist_lookup_flag(1, 1)
#define bktlist_flag_ins_tail	bktlist_lookup_flag(1, 0)
#define bktlist_flag_delete_front	bktlist_delete_flag(1)
#define bktlist_flag_delete_tail	bktlist_delete_flag(0)

struct __bktlist_key_type {
	u32 idx;
	u32 flags; 
};

struct {
	__uint(type, BPF_MAP_TYPE_STATIC_CUSTOM_MAP);
	__type(key, struct __bktlist_key_type);
	__type(value, __u32);  
	__uint(max_entries, 2);
 } bktlist SEC(".maps");

SEC("xdp")
int test_bktlist(struct xdp_md *ctx) {
        struct __bktlist_key_type key;
	u32 *value;
        int res = 0;
	u32 front = 1;
	u32 tail = 1;

	__builtin_memset(&key, 0, sizeof(key));
        log_info("testing bktlist operation\n");
      
	//insert front 
	key.idx = 1;

	log_info("testing ins front");
	key.flags = bktlist_flag_ins_front;
        value = bpf_map_lookup_elem(&bktlist, (void*)&key);
	xdp_assert_neq(NULL, value, "bktlist failed to insert front");
	*value = front;

	log_info("testing ins tail");
	key.flags = bktlist_flag_ins_tail;
        value =bpf_map_lookup_elem(&bktlist, (void*)&key);
	xdp_assert_neq(NULL, value, "bktlist failed to insert tail");
	*value = tail;

	log_info("testing lookup front");
	key.flags = bktlist_flag_lookup_front;
        value = bpf_map_lookup_elem(&bktlist, (void*)&key);
	xdp_assert_neq(NULL, value, "bktlist failed to lookup front");
	xdp_assert_eq(front, *value, "bktlist lookup front incorrect");
	
	log_info("testing lookup tail");
	key.flags = bktlist_flag_lookup_tail;
        value = bpf_map_lookup_elem(&bktlist, (void*)&key);
	xdp_assert_neq(NULL, value, "bktlist failed to lookup tail");
	xdp_assert_eq(tail, *value, "bktlist lookup tail incorrect");

	log_info("testing delete front");
	key.flags = bktlist_flag_delete_front;
        res = bpf_map_delete_elem(&bktlist, (void*)&key);
	xdp_assert_eq(0, res, "bktlist failed to delete front");


	key.flags = bktlist_flag_lookup_front;
        value = bpf_map_lookup_elem(&bktlist, (void*)&key);
        xdp_assert_neq(NULL, value, "bktlist failed to lookup front");
	xdp_assert_eq(tail, *value, "bktlist delete front incorrect");

	//reins front
	key.flags = bktlist_flag_ins_front;
        value = bpf_map_lookup_elem(&bktlist, (void*)&key);
	xdp_assert_neq(NULL, value, "bktlist failed to insert front");
	*value = front;


	log_info("testing delete tail");
	key.flags = bktlist_flag_delete_tail;
        res = bpf_map_delete_elem(&bktlist, (void*)&key);
	xdp_assert_eq(0, res, "bktlist failed to delete tail");

	key.flags = bktlist_flag_lookup_front;
        value = bpf_map_lookup_elem(&bktlist, (void*)&key);
	xdp_assert_neq(NULL, value, "bktlist failed to lookup front");
	xdp_assert_eq(front, *value, "bktlist delete tail incorrect");

	key.idx = 0;
	log_info("testing lookup front empty");
	key.flags = bktlist_flag_lookup_front;
        value = bpf_map_lookup_elem(&bktlist, (void*)&key);
	xdp_assert_eq(NULL, value, "bktlist empty lookup front return not NULL");

	log_info("testing lookup tail empty");
	key.flags = bktlist_flag_lookup_tail;
        value = bpf_map_lookup_elem(&bktlist, (void*)&key);
	xdp_assert_eq(NULL, value, "bktlist empty lookup tail return not NULL");

	log_info("testing delete empty front");
	key.flags = bktlist_flag_delete_front;
        res = bpf_map_delete_elem(&bktlist, (void*)&key);
	xdp_assert_eq(-2, res, "bktlist delete empty front incorrect");

	log_info("testing delete empty tail");
	key.flags = bktlist_flag_delete_tail;
        res = bpf_map_delete_elem(&bktlist, (void*)&key);
	xdp_assert_eq(-2, res, "bktlist delete empty tail incorrect");

	
        log_info("testing bktlist success\n");
        return XDP_PASS;      /*always not insert the mod*/

xdp_error:
        log_error("testing bktlist failed with res %d\n", res);
        return XDP_DROP;
}