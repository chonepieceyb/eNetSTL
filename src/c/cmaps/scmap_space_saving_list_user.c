#include "../common.h"
#include "../bpf_skel/scmap_space_saving_list.skel.h"

#define XDP_IF "ens2f0"

int main()
{
	BPF_XDP_SKEL_LOADER(scmap_space_saving_list, XDP_IF, xdp_main,
			    XDP_FLAGS_DRV_MODE)
}
