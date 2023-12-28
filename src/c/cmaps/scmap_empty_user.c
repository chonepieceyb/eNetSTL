#include "../common.h" 
#include "../bpf_skel/scmap_empty.skel.h"

#define IF_NAME "ens4np0"

int main() {
        BPF_XDP_SKEL_LOADER(scmap_empty, "ens4np0", xdp_main, XDP_FLAGS_DRV_MODE)
}