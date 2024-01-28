#include "common.h"

#include "bpf_skel/test_bpf_kptr_xchg.skel.h"

#define XDP_IF "ens4np0"

int main()
{
	BPF_XDP_SKEL_LOADER(test_bpf_kptr_xchg, XDP_IF, xdp_main,
			    XDP_FLAGS_DRV_MODE)
}
