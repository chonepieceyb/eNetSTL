#include "common.h"
#include "bpf_skel/test_bpf_cmp_alg_simd.skel.h"
#include <bpf/libbpf.h>

#define XDP_IF "ens4np0"

int __callback_load(struct test_bpf_cmp_alg_simd *skel)
{
	uint32_t arr[8] = { 1, 2, 3, 4, 5, 6, 7, 8 }, zero = 0;

	bpf_map__update_elem(skel->maps.arr_map, &zero, sizeof(zero), arr,
			     sizeof(arr), BPF_ANY);
	printf("initialized arr\n");

	return 0;
}

int main()
{
	BPF_XDP_SKEL_LOADER_WITH_CALLBACK(test_bpf_cmp_alg_simd, XDP_IF,
					  xdp_main, __callback_load,
					  XDP_FLAGS_DRV_MODE)
}
