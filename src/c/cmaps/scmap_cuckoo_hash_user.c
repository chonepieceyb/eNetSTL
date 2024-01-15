#include "../common.h"
#include "../bpf_skel/scmap_cuckoo_hash.skel.h"

#define XDP_IF "ens4np0"

int main()
{
	BPF_XDP_SKEL_LOADER(scmap_cuckoo_hash, XDP_IF, xdp_main,
			    XDP_FLAGS_DRV_MODE);
}
