#include "../common.h" 
#include "../bpf_skel/base_scmap_bktlist.skel.h"
#include "../test_helpers.h"

void test() {
        BPF_PROG_TEST_RUNNER("base_scmap_bktlist", base_scmap_bktlist, pkt_v4, test_bktlist, 1, XDP_PASS);
}

int main() {
        test();
}