#include "common.h"
#include "bpf_skel/test_parse_pkt_5tuple.skel.h"

#define XDP_IF "ens3f0"

int main()
{
	BPF_XDP_SKEL_LOADER(test_parse_pkt_5tuple, XDP_IF, xdp_main,
			    XDP_FLAGS_DRV_MODE)
}
