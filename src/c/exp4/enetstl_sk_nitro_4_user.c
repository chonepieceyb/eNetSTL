#include "../common.h"
#include "../config.h"

#include "../bpf_skel/enetstl_sk_nitro_4.skel.h"

int main()
{
	BPF_XDP_SKEL_LOADER(enetstl_sk_nitro_4, XDP_IF, xdp_main,
			    XDP_MODE)
}
