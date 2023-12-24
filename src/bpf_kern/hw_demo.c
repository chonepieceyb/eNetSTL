#include "common.h"

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
       // bpf_printk("empty xdp");
        return XDP_DROP;
}
