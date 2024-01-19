#include "common.h"
#include "bpf_skel/sk_cm2.skel.h"

#define XDP_IF "ens4np0"

int main()
{
	BPF_XDP_SKEL_LOADER(sk_cm2, XDP_IF, xdp_main, XDP_FLAGS_DRV_MODE)
}
