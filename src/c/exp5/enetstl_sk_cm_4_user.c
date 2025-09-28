#include "../common.h"
#include "../bpf_skel/enetstl_sk_cm_4.skel.h"
#include "../config.h"

int main()
{
	BPF_XDP_SKEL_LOADER(enetstl_sk_cm_4, XDP_IF, xdp_main,
			    XDP_MODE)
}