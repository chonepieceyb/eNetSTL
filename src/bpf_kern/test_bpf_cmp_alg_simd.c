#include "common.h"
#include "bpf_cmp_alg_simd.h"
#include "vmlinux.h"

static u32 index __attribute__((used));

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(
		value, struct { u32 data[8]; });
} arr_map SEC(".maps");

SEC("xdp") int xdp_main(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data,
	     *data_end = (void *)(long)ctx->data_end;
	u32 val, *arr, zero = 0;
	int i;

	arr = bpf_map_lookup_elem(&arr_map, &zero);
	if (!arr) {
		log_error("test_bpf_cmp_alg_simd: bpf_map_lookup_elem failed");
		goto out;
	}

	if (data + sizeof(val) > data_end) {
		log_error(
			"test_bpf_cmp_alg_simd: data + sizeof(val) > data_end");
		goto out;
	} else {
		val = *(u32 *)data;
	}

#if USE_IMPL == EBPF_IMPL
	log_debug("test_bpf_cmp_alg_simd: using eBPF implementation");
	for (i = 0; i < 8; i++) {
		if (val == arr[i]) {
			index = i;
			break;
		}
	}
#elif USE_IMPL == EBPF_WITH_HYPERCOM_INTRINSIC_IMPL
	log_debug(
		"test_bpf_cmp_alg_simd: using eBPF + HyperCom SIMD intrinsics implementation");
	index = bpf_find_u32_avx_emulated(arr, val);
#else
	log_debug("test_bpf_cmp_alg_simd: using HyperCom implementation");
	index = bpf_find_u32_avx(arr, val);
#endif

	log_debug("test_bpf_cmp_alg_simd: val = %u, index = %u", val, index);

out:
	return XDP_DROP;
}
