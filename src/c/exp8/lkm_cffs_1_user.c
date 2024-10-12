#include "../common.h"
#include "../config.h"
#include "../bpf_skel/lkm_cFFS.skel.h"

int main() {
	BPF_XDP_SKEL_LOADER(lkm_cFFS, XDP_IF, xdp_main, XDP_FLAGS_DRV_MODE)
}