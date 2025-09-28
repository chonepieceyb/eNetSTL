#include "../common.h"
#include "../config.h"

#include "../bpf_skel/ebpf_sk_nitro_4.skel.h"

int main()
{
	BPF_XDP_SKEL_LOADER(ebpf_sk_nitro_4, XDP_IF, xdp_main,
			    XDP_MODE)
}
