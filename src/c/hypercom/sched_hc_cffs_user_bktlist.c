#include "../common.h" 
#include "../bpf_skel/sched_hc_cFFS_PIQ_bktlist.skel.h"

int main() {
        BPF_XDP_SKEL_LOADER(sched_hc_cFFS_PIQ_bktlist, "ens4np0", xdp_main, XDP_FLAGS_DRV_MODE)
}