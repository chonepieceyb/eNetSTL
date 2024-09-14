#include "../common.h"
#include "../config.h"

#include "../bpf_skel/enetstl_cuckoo_hash.skel.h"

int main()
{
	BPF_XDP_SKEL_LOADER(enetstl_cuckoo_hash, XDP_IF, xdp_main,
			    XDP_FLAGS_DRV_MODE)
}