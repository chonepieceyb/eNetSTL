#include "common.h"

char _license[] SEC("license") = "GPL";

COUNT_MAP;

SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
        log_info("xdp_empty %d", 1);

	COUNT_MAP_INCREMENT;

out:
	return XDP_DROP;
}
