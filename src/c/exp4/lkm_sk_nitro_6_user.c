#include "../common.h"
#include "../config.h"

#include "../bpf_skel/lkm_sk_nitro.skel.h"

int main()
{
	BPF_XDP_SKEL_LOADER(lkm_sk_nitro, XDP_IF, xdp_main, XDP_FLAGS_DRV_MODE)
}
