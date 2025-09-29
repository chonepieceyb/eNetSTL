#include "../common.h"
#include "../config.h"

#include "../bpf_skel/lkm_cuckoo_hash.skel.h"

int main()
{
	BPF_XDP_SKEL_LOADER(lkm_cuckoo_hash, XDP_IF, xdp_main,
			    XDP_MODE)
}
