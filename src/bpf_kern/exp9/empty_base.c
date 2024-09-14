#include "../vmlinux.h"
#include "../common.h"

PACKET_COUNT_MAP_DEFINE

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	u32 __index = 0;
	struct pkt_count *current_count =
		bpf_map_lookup_elem(&count_map, &__index);
	if (current_count == NULL) {
		return XDP_DROP;
	}
	current_count->rx_count += 1;

	return XDP_DROP;
}
