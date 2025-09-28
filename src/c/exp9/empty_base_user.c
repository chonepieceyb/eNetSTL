#include "../common.h"
#include "../config.h"
#include "../bpf_skel/empty_base.skel.h"

int main() {
	BPF_XDP_SKEL_LOADER(empty_base, XDP_IF, xdp_main, XDP_MODE)
}