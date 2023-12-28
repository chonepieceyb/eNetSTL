#include "../common.h" 
#include "../bpf_skel/sched_scmap_cFFS_PIQ.skel.h"

int main() {
       BPF_XDP_SKEL_LOADER(sched_scmap_cFFS_PIQ, "ens4np0", xdp_main, XDP_FLAGS_DRV_MODE)
}