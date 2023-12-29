#include "../common.h" 
#include "../bpf_skel/sched_scmap_time_wheel.skel.h"
#include "../test_helpers.h"

void test() {
        BPF_PROG_TEST_RUNNER("sched_scmap_time_wheel", sched_scmap_time_wheel, pkt_v4, test_timewheel, 1, XDP_PASS);
}

int main() {
        test();
}