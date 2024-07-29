/*
 * @author chonepieceyb
 * testing BPF_STRUCT_OP for my st_demo 
 */
#include "../common.h"
#include <bpf/bpf_tracing.h>

#define ST_DEMO_OPS_NAME_MAX 16 

char _license[] SEC("license") = "GPL";

struct mod_struct_ops_ctx {
    int val;
};

struct mod_struct_ops_demo {
  int (*htss_loop_up_eBPF)(struct mod_struct_ops_ctx *ctx);
  int (*htss_update_eBPF)(struct mod_struct_ops_ctx *ctx);
  struct module *owner;
};

//struct st_demo_ctx_user {
//    __u64 first_val;
//};

//struct st_demo_ops {
//    int (*first_func)(struct st_demo_ctx *ctx);
//    char name[ST_DEMO_OPS_NAME_MAX];
//};

SEC("struct_ops/htss_loop_up_eBPF")
int BPF_PROG(bpf_htss_loop_up_eBPF, struct mod_struct_ops_ctx *c)
{
	bpf_printk("bpf_hello_world set mod_struct_ops_ctx->val  %d\n", c->val);
	return 0;
}

SEC("struct_ops/htss_update_eBPF")
int BPF_PROG(bpf_htss_update_eBPF, struct mod_struct_ops_ctx *c)
{
	bpf_printk("bpf_hello_world set mod_struct_ops_ctx->val  %d\n", c->val);
	return 0;
}

SEC(".struct_ops")
struct mod_struct_ops_demo test_st_op = {
	.htss_loop_up_eBPF     = (void *)bpf_htss_loop_up_eBPF,
	.htss_update_eBPF     = (void *)bpf_htss_update_eBPF,
};