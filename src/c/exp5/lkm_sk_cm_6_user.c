#include "../common.h"
#include "../bpf_skel/lkm_sk_cm.skel.h"
#include "../config.h"

int main()
{
	BPF_XDP_SKEL_LOADER(lkm_sk_cm, XDP_IF, xdp_main, XDP_MODE)
}