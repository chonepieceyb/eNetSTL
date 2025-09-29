#include "../common.h" 
#include "../bpf_skel/ebpf_carausel_tw_4.skel.h"
#include "../config.h"

int main() {
        BPF_XDP_SKEL_LOADER(ebpf_carausel_tw_4, XDP_IF, xdp_main, XDP_MODE)
}