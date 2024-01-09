#include "common.h"
#include "bpf_cmp_alg_simd.h"

#define EBPF 1
#define CMP_KFUNC 2
#define USE_IMPL CMP_KFUNC

static u8 index;

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data,
	     *data_end = (void *)(long)ctx->data_end;
	u32 val, arr[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	int i;

	if (data + sizeof(val) > data_end) {
		goto out;
	} else {
		val = *(u32 *)data;
	}

#if USE_IMPL == EBPF
	index = -1;
	for (i = 0; i < sizeof(arr) / sizeof(arr[0]); i++) {
		if (val == arr[i]) {
			index = i;
			break;
		}
	}
#else
	index = bpf_find_u32_avx2(arr, val);
#endif

	log_debug("test_bpf_cmp_alg_simd: val = %u, index = %u", val, index);

out:
	return XDP_DROP;
}
