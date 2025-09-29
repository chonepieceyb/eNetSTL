#include "../common.h"
#include "../bpf_skel/ebpf_sk_cm_2.skel.h"
#include "../config.h"

int main()
{
	BPF_XDP_SKEL_LOADER(ebpf_sk_cm_2, XDP_IF, xdp_main, XDP_MODE)
}