#include "../common.h"
#include "../bpf_skel/scmap_empty_update.skel.h"

#define IF_NAME "ens4np0"

int main()
{
	BPF_XDP_SKEL_LOADER(scmap_empty_update, IF_NAME, xdp_main,
			    XDP_FLAGS_DRV_MODE)
}
