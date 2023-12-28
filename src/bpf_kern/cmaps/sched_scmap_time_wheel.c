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

SEC("xdp")
int test_timewheel(void *ctx)
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
int xdp_main(void *ctx)
{
	int res;
	unsigned long ct = bpf_get_current_time();
	struct __tw_value_type timer  = {
		.expires = ct + 1,
	};
	res = bpf_map_push_elem(&time_wheel_map, &timer, 0);
	xdp_assert_eq(0, res, "time_wheel_map failed to push elem");

	struct __tw_value_type expire_timers = {0};
	res = bpf_map_pop_elem(&time_wheel_map, &expire_timers);
	xdp_assert_eq(0, res, "time_wheel_map failed to pop elem");
	
	return XDP_DROP;
xdp_error:;
	log_error("xdp_error with res %d", res);
	return XDP_DROP;
}