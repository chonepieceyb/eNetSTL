#include "common.h"
#include "bpf_cmp_alg_simd.h"

static u8 index __attribute__((used));

char _license[] SEC("license") = "GPL";
unsigned int arr[8];

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data,
	     *data_end = (void *)(long)ctx->data_end;
	u32 val;
	int i;

	if (data + sizeof(val) > data_end) {
		log_error(
			"test_bpf_cmp_alg_simd: data + sizeof(val) > data_end");
		goto out;
	} else {
		val = *(u32 *)data;
	}

#ifdef USE_EBPF_IMPL
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
