#include "../common.h"


char _license[] SEC("license") = "GPL";

/********************************************/
/**************TW defines********************
**********************************************/

/*TW implementation from linux 2.6.11*/

//#define TVN_BITS 6
//#define TVR_BITS 8


#define TVN_BITS 6
#define TVR_BITS 8

#define TVN_SIZE (1 << TVN_BITS)
#define TVR_SIZE (1 << TVR_BITS)

/* NUM_TIME_WHEELS must be consistent with the LKM side */
#define NUM_TIME_WHEELS 2

// #define TIMER_MAX_TIMEOUT (1 << (TVR_BITS + TVN_BITS * (NUM_TIME_WHEELS - 1)))
#define TIMER_MAX_TIMEOUT 512

extern __u64 bpf_get_current_time(void) __ksym;

struct __tw_value_type {
        unsigned long expires;
};

struct {
	__uint(type, BPF_MAP_TYPE_STATIC_CUSTOM_MAP);
	__type(key, int);
	__type(value, struct __tw_value_type);  
	__uint(max_entries, TVR_SIZE + TVN_SIZE);
} time_wheel_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, u64);
	__uint(max_entries, 1);
} num_runs_map SEC(".maps");

PACKET_COUNT_MAP_DEFINE

SEC("xdp")
int test_timewheel(struct xdp_md *ctx)
{
	int res;
	unsigned long ct = bpf_get_current_time();
	struct __tw_value_type timer  = {
		.expires = ct + 1,
	};
	res = bpf_map_push_elem(&time_wheel_map, &timer, 0);
	xdp_assert_eq(0, res, "time_wheel_map failed to push elem");

	log_info("waiting timer");
	struct __tw_value_type expire_timers = {0};
	res = bpf_map_pop_elem(&time_wheel_map, &expire_timers);
	xdp_assert_eq(0, res, "time_wheel_map failed to pop elem");
	
	log_info("expire %lu elems", *(u64*)(&expire_timers));
	return XDP_PASS;

xdp_error:;
	log_error("xdp_error with res %d", res);
	return XDP_DROP;
}

/*for performance testing*/
SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	LATENCY_START_TIMESTAMP_DEFINE

	int res, zero = 0;
	unsigned long ct;
	struct __tw_value_type timer;
	u64 *num_runs_ptr, num_runs;

	num_runs_ptr = bpf_map_lookup_elem(&num_runs_map, &zero);
	if (num_runs_ptr != NULL) {
		num_runs = *num_runs_ptr + 1;
		*num_runs_ptr = num_runs;
	} else {
		log_error("failed to get num runs");
		res = -EFAULT;
		goto xdp_error;
	}
	log_debug("num_runs %llu, timeout %u", num_runs,
		  num_runs & (TIMER_MAX_TIMEOUT - 1));

	ct = bpf_get_current_time();
	timer.expires = ct + (num_runs & (TIMER_MAX_TIMEOUT - 1));
	res = bpf_map_push_elem(&time_wheel_map, &timer, 0);
	xdp_assert_eq(0, res, "time_wheel_map failed to push elem");

	struct __tw_value_type expire_timers = {0};
	res = bpf_map_pop_elem(&time_wheel_map, &expire_timers);
	xdp_assert_eq(0, res, "time_wheel_map failed to pop elem");

	PACKET_COUNT_MAP_UPDATE

#ifdef LATENCY_EXP
	SWAP_MAC_AND_RETURN_XDP_TX(ctx) 
#endif
	return XDP_DROP;
xdp_error:;
	log_error("xdp_error with res %d", res);
	return XDP_DROP;
}