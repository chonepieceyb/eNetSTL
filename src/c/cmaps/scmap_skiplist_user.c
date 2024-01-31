#include "../common.h" 
#include "../bpf_skel/scmap_skiplist.skel.h"
#include "../test_helpers.h"

void test() {
        BPF_PROG_TEST_RUNNER("scmap_skiplist", scmap_skiplist, pkt_v4, xdp_test, 1, 0);
}
int main() {
//        test();
//        return 0;
       BPF_XDP_SKEL_LOADER(scmap_skiplist, "ens4np0", add_test, XDP_FLAGS_DRV_MODE)
}