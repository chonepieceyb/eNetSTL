#include "../common.h" 
#include "../bpf_skel/sched_hc_cFFS_PIQ.skel.h"
#include "../test_helpers.h"

void test() {
        BPF_PROG_TEST_RUNNER("test shced_hc_cFFS_PIQ", sched_hc_cFFS_PIQ, pkt_v4, test_hffs, 1, XDP_PASS);
}

int main() {
        test();
}