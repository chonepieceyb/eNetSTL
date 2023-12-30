#include "../common.h" 
#include "../bpf_skel/sched_hc_time_wheel.skel.h"

int main() {
        BPF_XDP_SKEL_LOADER(sched_hc_time_wheel, "ens4np0", xdp_main, XDP_FLAGS_DRV_MODE)
}