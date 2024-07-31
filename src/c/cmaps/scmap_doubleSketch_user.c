#include "../common.h" 
#include "../bpf_skel/scmap_doubleSketch.skel.h"

int main() {
       BPF_XDP_SKEL_LOADER(scmap_doubleSketch, "ens2f0", xdp_main, XDP_FLAGS_DRV_MODE)
}