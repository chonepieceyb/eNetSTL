#include "../common.h"
#include "../config.h"

#include "../bpf_skel/enetstl_sk_nitro_8.skel.h"

int main()
{
	BPF_XDP_SKEL_LOADER(enetstl_sk_nitro_8, XDP_IF, xdp_main,
			    XDP_FLAGS_DRV_MODE)
}