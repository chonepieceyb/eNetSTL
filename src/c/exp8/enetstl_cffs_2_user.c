#include "../common.h"
#include "../config.h"
#include "../bpf_skel/enetstl_cFFS_2.skel.h"

int main() {
	BPF_XDP_SKEL_LOADER(enetstl_cFFS_2, XDP_IF, xdp_main, XDP_FLAGS_DRV_MODE)
}