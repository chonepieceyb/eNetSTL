#include "../common.h"
#include "../config.h"
#include "../bpf_skel/ebpf_cFFS_2.skel.h"

int main() {
	BPF_XDP_SKEL_LOADER(ebpf_cFFS_2, XDP_IF, xdp_main, XDP_FLAGS_DRV_MODE)
}