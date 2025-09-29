#include "../common.h"
#include "../bpf_skel/enetstl_sk_cm_8.skel.h"
#include "../config.h"

int main()
{
	BPF_XDP_SKEL_LOADER(enetstl_sk_cm_8, XDP_IF, xdp_main,
			    XDP_MODE)
}