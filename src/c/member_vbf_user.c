#include "common.h" 
#include "bpf_skel/member_vbf.skel.h"

int main() {
	BPF_XDP_SKEL_LOADER(member_vbf, "ens4np0", xdp_main, XDP_FLAGS_DRV_MODE)
}