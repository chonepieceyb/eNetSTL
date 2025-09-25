#include "../common.h"
#include "../bpf_skel/ebpf_cuckoo_hash_dp.skel.h"
#include "../config.h"


int main()
{
	BPF_XDP_SKEL_LOADER(ebpf_cuckoo_hash_dp, XDP_IF, xdp_main, XDP_FLAGS_DRV_MODE)
}