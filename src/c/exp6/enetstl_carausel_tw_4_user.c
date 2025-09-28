#include "../common.h" 
#include "../bpf_skel/enetstl_carausel_tw_4.skel.h"
#include "../config.h"

int main() {
        BPF_XDP_SKEL_LOADER(enetstl_carausel_tw_4, XDP_IF, xdp_main, XDP_MODE)
}

// #include "../test_helpers.h"

// void test() {
//         BPF_PROG_TEST_RUNNER("enetstl_carausel_tw_4", enetstl_carausel_tw_4, pkt_v4, test_timewheel, 1, 0);
// }

// int main() {
//         test();
// }