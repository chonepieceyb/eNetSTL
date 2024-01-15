#include "common.h"
#include "bpf_skel/space_saving.skel.h"

#define XDP_IF "ens4np0"

int main()
{
	BPF_XDP_SKEL_LOADER(space_saving, XDP_IF, xdp_main, XDP_FLAGS_DRV_MODE)
}
