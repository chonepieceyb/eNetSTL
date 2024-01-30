#include "../common.h"
#include "../bpf_skel/hypercom_efd.skel.h"

#define XDP_IF "ens4np0"

int main()
{
	BPF_XDP_SKEL_LOADER(hypercom_efd, XDP_IF, xdp_main, XDP_FLAGS_DRV_MODE)
}
