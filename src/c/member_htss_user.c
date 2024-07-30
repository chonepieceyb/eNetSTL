#include "common.h" 
#include "bpf_skel/member_htss.skel.h"

int main() {
	BPF_XDP_SKEL_LOADER(member_htss, "ens2f0", xdp_main, XDP_FLAGS_DRV_MODE)
}