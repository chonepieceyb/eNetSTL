#include "common.h"

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
        log_info("xdp_empty %d", 1);
        return XDP_DROP;
}
