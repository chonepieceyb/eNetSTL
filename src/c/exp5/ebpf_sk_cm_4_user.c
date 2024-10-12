#include "../common.h"
#include "../bpf_skel/ebpf_sk_cm_4.skel.h"
#include "../config.h"

int main()
{
	BPF_XDP_SKEL_LOADER(ebpf_sk_cm_4, XDP_IF, xdp_main, XDP_FLAGS_DRV_MODE)
}