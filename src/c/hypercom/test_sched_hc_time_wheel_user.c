#include "../common.h" 
#include "../bpf_skel/sched_hc_time_wheel.skel.h"
#include "../test_helpers.h"

void test() {
        BPF_PROG_TEST_RUNNER("sched_hc_time_wheel", sched_hc_time_wheel, pkt_v4, test_timewheel, 1, 0);
}

int main() {
        test();
}