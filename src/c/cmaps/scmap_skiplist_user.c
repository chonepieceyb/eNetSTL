#include "../common.h" 
#include "../bpf_skel/scmap_skiplist.skel.h"

int main() {
       BPF_XDP_SKEL_LOADER(scmap_skiplist, "ens4np0", xdp_main, XDP_FLAGS_DRV_MODE)
}