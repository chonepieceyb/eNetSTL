#include "common.h" 
#include "bpf_skel/rake_limit.skel.h"

int main() {
	BPF_XDP_SKEL_LOADER(rake_limit, "ens4np0", xdp_main, XDP_FLAGS_DRV_MODE)
}