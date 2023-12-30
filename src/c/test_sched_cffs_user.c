#include "common.h" 
#include "bpf_skel/sched_cFFS_PIQ.skel.h"
#include "test_helpers.h"

void test1() {
        BPF_PROG_TEST_RUNNER("sched_cffs_piq", sched_cFFS_PIQ, pkt_v4, test_hffs1, 1, XDP_PASS);
}

void test2() {
        BPF_PROG_TEST_RUNNER("sched_cffs_piq", sched_cFFS_PIQ, pkt_v4, test_hffs2, 100, XDP_PASS);
}

int main() {
        test1();
        test2();
}