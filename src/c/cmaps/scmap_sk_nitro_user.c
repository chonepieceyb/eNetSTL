#include "../common.h"
#include "../bpf_skel/scmap_sk_nitro.skel.h"

#define XDP_IF "ens4np0"

int main()
{
	BPF_XDP_SKEL_LOADER(scmap_sk_nitro, XDP_IF, xdp_main,
			    XDP_FLAGS_DRV_MODE)
}
