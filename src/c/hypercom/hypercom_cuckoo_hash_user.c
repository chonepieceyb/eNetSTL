#include "../common.h"
#include "../bpf_skel/hypercom_cuckoo_hash.skel.h"

#include "../test_helpers.h"

#define XDP_IF "ens4np0"

int main()
{
	BPF_XDP_SKEL_LOADER(hypercom_cuckoo_hash, XDP_IF, xdp_main,
			    XDP_FLAGS_DRV_MODE)
}
