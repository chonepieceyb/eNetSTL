#include "../common.h" 
#include "../bpf_skel/member_scmap_htss.skel.h"

int main() {
       BPF_XDP_SKEL_LOADER(member_scmap_htss, "ens2f0", xdp_main, XDP_FLAGS_DRV_MODE)
}