#include "../common.h" 
#include "../config.h"
#include "../bpf_skel/lkm_htss.skel.h"

int main() {
	BPF_XDP_SKEL_LOADER(lkm_htss, XDP_IF, xdp_main, XDP_MODE)
}