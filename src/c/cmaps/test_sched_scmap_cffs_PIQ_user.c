#include "../common.h" 
#include "../bpf_skel/sched_scmap_cFFS_PIQ.skel.h"
#include "../test_helpers.h"

void test1() {
        BPF_PROG_TEST_RUNNER("sched_scmap_cFFS_PIQ", sched_scmap_cFFS_PIQ, pkt_v4, test_cffs, 20, XDP_PASS);
}

void test2() {
        BPF_PROG_TEST_RUNNER("sched_scmap_cFFS_PIQ", sched_scmap_cFFS_PIQ, pkt_v4, xdp_main, 1, XDP_DROP);
}

int main() {
        test1();
        test2();
}