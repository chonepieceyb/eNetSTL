#define  TIME_SHIFT 14
#include "enetstl_tw.h"

char _license[] SEC("license") = "GPL";

/********************************************/
/**************TW defines********************
**********************************************/

SEC("xdp")
int test_timewheel(struct xdp_md *ctx)
{
	int key = 0, res;
	unsigned long ct = get_current_time();
	struct time_wheel_queue *twq;
	struct bktlists *bktlists_map;
	twq = bpf_map_lookup_elem(&time_wheel_map, &key);
	xdp_assert_neq(NULL, twq, "failed to lookup time_wheel_map");
	bktlists_map = bpf_map_lookup_elem(&bpf_bktlist_map, &key);
	xdp_assert_neq(NULL, bktlists_map, "failed to lookup bktlists_map");
	
	
	//struct bpf_bkt_list *bktlist = bktlists_get_or_create(twq);
	if (unlikely(!bktlists_map->fd)) {
		struct bpf_bkt_list * new_bktlists = bpf_bktlist_new();
		if (unlikely(new_bktlists == NULL)) {
			log_error("failed to alloc bktlist");
			goto xdp_error;
		}
		bktlists_map->fd = new_bktlists->fd;
		struct bpf_bkt_list *old_bktlists = bpf_kptr_xchg(&bktlists_map->map, new_bktlists);
		if (unlikely(old_bktlists != NULL)) {
			bpf_bktlist_free(old_bktlists);
			log_error("bktlist have init");
			goto xdp_error;
		}
	}

	if (unlikely(!twq->init)) {
		log_debug("init current time %lu", ct);
		twq->cnt = 0;
		twq->clk = ct;
		twq->init = 1;
        }

        unsigned long expires = ct + 4;
	struct bpf_time_list timer = {
		.expires = expires,
	};
        res = __add_timer_on(twq, bktlists_map->fd, expires, &timer);
	xdp_assert_eq(0, res, "_add_timer_on failed");
	twq->cnt += 1;
	#if LOG_LEVEL > LOG_LEVEL_DEBUG
		current_time_g += 4;
	#endif 
        
        res = __run_timer(twq, bktlists_map->fd);
	xdp_assert_eq(0, res, "failed run timer");
	log_debug("current clk  %lu", twq->clk);
        log_debug("test success");
	
	return 0;
xdp_error:;
	return 1;
}

/*for performance testing*/
SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	LATENCY_START_TIMESTAMP_DEFINE

	int key = 0, res;
	unsigned long ct = get_current_time();
	u64 num_runs, *num_runs_ptr;
	struct time_wheel_queue *twq;
	struct bktlists *bktlists_map;

	num_runs_ptr = bpf_map_lookup_elem(&num_runs_map, &key);
	xdp_assert_neq(NULL, num_runs_ptr, "failed to lookup num_runs_map");

	twq = bpf_map_lookup_elem(&time_wheel_map, &key);
	xdp_assert_neq(NULL, twq, "failed to lookup time_wheel_map");

	bktlists_map = bpf_map_lookup_elem(&bpf_bktlist_map, &key);
	xdp_assert_neq(NULL, bktlists_map, "failed to lookup bktlists_map");

	num_runs = *num_runs_ptr + 1;
	*num_runs_ptr = num_runs;

	log_debug("init current time %lu", ct);
	if (unlikely(!bktlists_map->fd)) {
		struct bpf_bkt_list * new_bktlists = bpf_bktlist_new();
		if (unlikely(new_bktlists == NULL)) {
			log_error("failed to alloc bktlist");
			goto xdp_error;
		}
		bktlists_map->fd = new_bktlists->fd;
		struct bpf_bkt_list *old_bktlists = bpf_kptr_xchg(&bktlists_map->map, new_bktlists);
		if (unlikely(old_bktlists != NULL)) {
			bpf_bktlist_free(old_bktlists);
			log_error("bktlist have init");
			goto xdp_error;
		}
	}

	if (unlikely(!twq->init)) {
		log_debug("init current time %lu", ct);
		twq->cnt = 0;
		twq->clk = ct;
		twq->init = 1;
        }

	log_debug("num runs %llu, timeout %u", num_runs,
		  num_runs & (TIMER_MAX_TIMEOUT - 1));

	unsigned long expires = ct + (num_runs & (TIMER_MAX_TIMEOUT - 1));

	struct bpf_time_list timer = {
		.expires = expires
	};
	res = __add_timer_on(twq, bktlists_map->fd, expires, &timer);
	
	xdp_assert_eq(0, res, "__add_timer_on failed");
        twq->cnt += 1;
        
        res = __run_timer(twq, bktlists_map->fd);
	xdp_assert_eq(0, res, "failed run timer");
	log_debug("current clk  %lu", twq->clk);
	
	PACKET_COUNT_MAP_UPDATE
#ifdef LATENCY_EXP
	SWAP_MAC_AND_RETURN_XDP_TX(ctx) 
#endif
	return XDP_DROP;
xdp_error:;
	return XDP_DROP;
}