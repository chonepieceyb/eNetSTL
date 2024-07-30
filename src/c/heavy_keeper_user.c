#include "common.h"
#include "bpf_skel/heavy_keeper.skel.h"

#define XDP_IF "ens2f0"

int main()
{
	BPF_XDP_SKEL_LOADER(heavy_keeper, XDP_IF, xdp_main, XDP_FLAGS_DRV_MODE)
}
