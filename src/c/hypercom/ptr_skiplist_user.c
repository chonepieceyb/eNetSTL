#include "../common.h" 
#include "../bpf_skel/ptr_skiplist.skel.h"

int main() {
        BPF_XDP_SKEL_LOADER(ptr_skiplist, "ens4np0", xdp_main_lookup_lite, XDP_FLAGS_DRV_MODE)
}