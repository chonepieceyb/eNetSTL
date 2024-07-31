#include "../common.h"

#include <bpf/bpf_tracing.h>

#define USE_CALLBACK_PARAM_COUNT 5

#if USE_CALLBACK_PARAM_COUNT == 0
extern int empty_primitive(void) __ksym;
#elif USE_CALLBACK_PARAM_COUNT == 1
extern int empty_primitive(u64 param1) __ksym;
#elif USE_CALLBACK_PARAM_COUNT == 5
extern int empty_primitive(u64 param1, u64 param2, u64 param3, u64 param4,
			   u64 param5) __ksym;
#else
#error "Unsupported USE_CALLBACK_PARAM_COUNT"
#endif

struct empty_scmap_struct_ops {
#if USE_CALLBACK_PARAM_COUNT == 0
	int (*callback)(void);
#elif USE_CALLBACK_PARAM_COUNT == 1
	int (*callback)(u64 param1);
#elif USE_CALLBACK_PARAM_COUNT == 5
	int (*callback)(u64 param1, u64 param2, u64 param3, u64 param4,
			u64 param5);
#else
#error "Unsupported USE_CALLBACK_PARAM_COUNT"
#endif
	struct module *owner;
};

char _license[] SEC("license") = "GPL";

#if USE_CALLBACK_PARAM_COUNT == 0
SEC("struct_ops/empty_scmap_callback")
int BPF_PROG(empty_cb_callback)
{
	return empty_primitive();
}
#elif USE_CALLBACK_PARAM_COUNT == 1
SEC("struct_ops/empty_scmap_callback")
int BPF_PROG(empty_cb_callback, u64 param1)
{
	return empty_primitive(param1);
}
#elif USE_CALLBACK_PARAM_COUNT == 5
SEC("struct_ops/empty_scmap_callback")
int BPF_PROG(empty_cb_callback, u64 param1, u64 param2, u64 param3, u64 param4,
	     u64 param5)
{
	return empty_primitive(param1, param2, param3, param4, param5);
}
#else
#error "Unsupported USE_CALLBACK_PARAM_COUNT"
#endif

SEC(".struct_ops")
struct empty_scmap_struct_ops empty_cb_ops = {
	.callback = (void *)empty_cb_callback,
};
