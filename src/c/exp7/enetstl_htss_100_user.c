#include "../common.h"
#include "../config.h"
#include "../bpf_skel/enetstl_htss_100.skel.h"

int main() {
	BPF_XDP_SKEL_LOADER(enetstl_htss_100, XDP_IF, xdp_main, XDP_FLAGS_DRV_MODE)
}