#include "vmlinux.h"
#include "common.h"

#include "bpf_random_base_alg.h"

#define SK_NITRO_UPDATE_PROB_PERCENT 10

char _license[] SEC("license") = "GPL";

static const uint32_t thres = (SK_NITRO_UPDATE_PROB_PERCENT / 100.0) * (u32)-1;
static uint32_t dummy = 0;

struct geo_sampling_ctx_holder {
	struct geo_sampling_ctx __kptr *ctx;
	geo_cnt_t cnt_alt;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct geo_sampling_ctx_holder);
	__uint(max_entries, 1);
} geo_sampling_ctx_map SEC(".maps");

static inline int xdp_main_ebpf(struct xdp_md *ctx)
{
	uint32_t random = bpf_get_prandom_u32();
	if (random < thres) {
		dummy++;
	}

	return XDP_DROP;
}

static inline int xdp_main_hypercom(struct xdp_md *ctx)
{
	struct geo_sampling_ctx_holder *geo_ctx_holder;
	struct geo_sampling_ctx *geo_ctx, *old_geo_ctx;
	int zero = 0;

	geo_ctx_holder = bpf_map_lookup_elem(&geo_sampling_ctx_map, &zero);
	if (!geo_ctx_holder) {
		log_error(" Invalid entry in the geo sampling context map");
		goto out;
	}

	if (geo_ctx_holder->cnt_alt > 0) {
		geo_ctx_holder->cnt_alt--;
		goto out;
	}

	geo_ctx = bpf_kptr_xchg(&geo_ctx_holder->ctx, NULL);
	if (!geo_ctx) {
		geo_ctx = bpf_geo_sampling_ctx_new();
		if (!geo_ctx) {
			log_error("Failed to allocate geo sampling context");
			goto out_xchg_kptr;
		}
	}

	dummy++;
	geo_ctx_holder->cnt_alt = bpf_geo_sampling_gen_geo_cnt(geo_ctx);

out_xchg_kptr:
	old_geo_ctx = bpf_kptr_xchg(&geo_ctx_holder->ctx, geo_ctx);
	if (old_geo_ctx != NULL) {
		bpf_geo_sampling_ctx_free(old_geo_ctx);
	}

out:
	return XDP_DROP;
}

SEC("xdp") int xdp_main(struct xdp_md *ctx)
{
#if USE_IMPL == EBPF_IMPL
	return xdp_main_ebpf(ctx);
#else
	return xdp_main_hypercom(ctx);
#endif
}
