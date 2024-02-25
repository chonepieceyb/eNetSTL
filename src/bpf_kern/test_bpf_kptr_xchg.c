#include "vmlinux.h"

#include "common.h"
#include "bpf_random_base_alg.h"

char _license[] SEC("license") = "GPL";

static u64 dummy __attribute__((used));

struct geo_sampling_ctx_holder {
	struct geo_sampling_ctx __kptr *ctx;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct geo_sampling_ctx_holder);
	__uint(max_entries, 1);
} geo_sampling_ctx_map SEC(".maps");

SEC("xdp") int xdp_main(struct xdp_md *ctx)
{
	uint32_t zero = 0;
	struct geo_sampling_ctx_holder *holder;
	struct geo_sampling_ctx *geo_ctx;

	holder = bpf_map_lookup_elem(&geo_sampling_ctx_map, &zero);
	if (!holder) {
		log_error(" cannot find holder");
		goto out;
	}

	geo_ctx = bpf_kptr_xchg(&holder->ctx, NULL);
	dummy = (u64)geo_ctx;
	if (geo_ctx == NULL) {
		log_debug(" geo_ctx is NULL");
		goto out;
	}

	geo_ctx = bpf_kptr_xchg(&holder->ctx, geo_ctx);
	if (geo_ctx) {
		bpf_geo_sampling_ctx_free(geo_ctx);
	}

out:
	return XDP_DROP;
}
