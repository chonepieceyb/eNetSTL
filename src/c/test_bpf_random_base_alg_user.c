#include "common.h"

#include "bpf_skel/test_bpf_random_base_alg.skel.h"

#define XDP_IF "ens4np0"

int main()
{
	BPF_XDP_SKEL_LOADER(test_bpf_random_base_alg, XDP_IF, xdp_main,
			    XDP_FLAGS_DRV_MODE)
}
