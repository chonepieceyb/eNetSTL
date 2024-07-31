#include "../common.h"
#include "../bpf_skel/scmap_empty_lookup.skel.h"

#define IF_NAME "ens4np0"

int main()
{
	BPF_XDP_SKEL_LOADER(scmap_empty_lookup, IF_NAME, xdp_main,
			    XDP_FLAGS_DRV_MODE)
}
