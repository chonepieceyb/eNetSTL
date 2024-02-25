#include "common.h"
#include "bpf_skel/sk_cm.skel.h"

#define XDP_IF "ens4np0"

int main()
{
	BPF_XDP_SKEL_LOADER(sk_cm, XDP_IF, xdp_main, XDP_FLAGS_DRV_MODE)
}
