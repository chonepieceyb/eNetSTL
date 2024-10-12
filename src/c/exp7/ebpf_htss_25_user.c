#include "../common.h"
#include "../config.h"
#include "../bpf_skel/ebpf_htss_25.skel.h"

int main() {
	BPF_XDP_SKEL_LOADER(ebpf_htss_25, XDP_IF, xdp_main, XDP_FLAGS_DRV_MODE)
}