#include "common.h"
#include "bpf_skel/test_bpf_cmp_alg_simd.skel.h"

#define XDP_IF "ens4np0"

int __callback_load(struct test_bpf_cmp_alg_simd *skel)
{
	int i;

	for (i = 0; i < sizeof(skel->bss->arr) / sizeof(skel->bss->arr[0]);
	     i++) {
		skel->bss->arr[i] = i + 1;
	}
	printf("initialized arr\n");

	return 0;
}

int main()
{
	BPF_XDP_SKEL_LOADER_WITH_CALLBACK(test_bpf_cmp_alg_simd, XDP_IF,
					  xdp_main, __callback_load,
					  XDP_FLAGS_DRV_MODE)
}
