#define ELEM_NUM (4096*4)

#include "nfdchs_skiplist.h"

PACKET_COUNT_MAP_DEFINE

static sl_value_type lookup_res = {0};

SEC("xdp")
int xdp_main(struct xdp_md *ctx) 
{
        LATENCY_START_TIMESTAMP_DEFINE

        int key = 0; 
        int res;
        struct value_type *mval;
        mval = bpf_map_lookup_elem(&mymap, &key);
        xdp_assert_neq(NULL, mval, "map lookup failed");
        struct ptr_node_container *sl = container_get_or_create(mval);
        xdp_assert_neq(NULL, sl, "failed to get sl");
        
        if (unlikely(!mval->init)) {
                res = init_skiplist_lite(sl, &mval->cnt);
                xdp_assert_eq_tag(0, res, "init skiplist failed", drop_sl); /*found*/
                mval->init = true;
        }
        log_debug("init success");
        /*testing*/
        sl_key_type k = {0};
        u64 vv = bpf_get_prandom_u32() & (ELEM_NUM - 1);
        *(u64*)(&k) = vv;

        // /*grow the packet*/
        // u64 packet_size = 14;
        // res = bpf_xdp_adjust_tail(ctx, VALUE_SIZE);
        // xdp_assert_eq_tag(0, res, "failed to grow packet", drop_sl); /*found*/
        // void *data = (void *)(__u64)ctx->data;
        // void *data_end = (void *)(__u64)ctx->data_end;
        // sl_value_type *look_res = (sl_value_type *)(data + packet_size);
        // if ((void*)(look_res + 1) > data_end) {
        //         log_error("packet too small should not happen");
        //         goto drop_sl;
        // }

        //res = sl_get_lite(sl, &k, &res_v, &mval->cnt);
        res = sl_get_lite(sl, &k, &lookup_res, &mval->cnt);
        xdp_assert_eq_tag(0, res, "not found", drop_sl); /*found*/


        struct ptr_node_container * oldsl = bpf_kptr_xchg(&mval->container, sl);
        if (unlikely(oldsl != NULL)) {
              ptr_destory_node_container(oldsl);  
        }

        PACKET_COUNT_MAP_UPDATE
#ifdef LATENCY_EXP
	SWAP_MAC_AND_RETURN_XDP_TX(ctx) 
#endif
        return XDP_DROP;

drop_sl:
        ptr_destory_node_container(sl);
xdp_error:
        return XDP_DROP;
}