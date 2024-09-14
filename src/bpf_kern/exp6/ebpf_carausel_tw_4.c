#define TIME_SHIFT 12 

#include "ebpf_tw.h"

char _license[] SEC("license") = "GPL";

PACKET_COUNT_MAP_DEFINE

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	LATENCY_START_TIMESTAMP_DEFINE

	int key = 0, res;
	__u32 cpu = bpf_get_smp_processor_id();
	struct time_wheel_queue *tq;
	tq = bpf_map_lookup_elem(&time_wheel_map, &key);
	xdp_assert_neq(NULL, tq, "failed to lookup time_wheel_map");
	unsigned long ct = get_current_time();
	log_debug("init current time %lu", ct);
	if (unlikely(tq->init == 0)) {
		tq->cnt = 0;
		tq->clk = ct;
		tq->init = 1;
	}

	struct bpf_time_list *elem;
	elem = bpf_obj_new(typeof(*elem));
	xdp_assert_neq(NULL, elem, "elem = bpf_obj_new() failed ");

	u64 num_runs, *num_runs_ptr = bpf_map_lookup_elem(&num_runs_map, &key);
	if (num_runs_ptr != NULL) {
		num_runs = *num_runs_ptr + 1;
		*num_runs_ptr = num_runs;
	} else {
		log_error("failed to lookup num_runs_map");
		bpf_obj_drop(elem);
		goto xdp_error;
	}

	log_debug("num_runs %llu, timeout %u", num_runs,
		  num_runs & (TIMER_MAX_TIMEOUT - 1));

	elem->expires = ct + (num_runs & (TIMER_MAX_TIMEOUT - 1));

	res = add_timer_on(cpu, tq, &time_wheel_bkt_map, elem);
	if (res != 0 && res != -22) {
		bpf_obj_drop(elem);
	}
	xdp_assert_eq(0, res, "failed add timer");

	res = __run_timer(cpu, tq, &time_wheel_bkt_map);
	xdp_assert_eq(0, res, "failed run timer");
	log_debug("current clk  %lu", tq->clk);

	PACKET_COUNT_MAP_UPDATE

#ifdef LATENCY_EXP
	SWAP_MAC_AND_RETURN_XDP_TX(ctx) 
#endif

	return XDP_DROP;

xdp_error:;
	return XDP_DROP;
}