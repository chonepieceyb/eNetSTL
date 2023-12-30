#include "common.h" 
#include "bpf_skel/sched_time_wheel.skel.h"
#include "test_helpers.h"

void test1() {
        BPF_PROG_TEST_RUNNER("test sched_time_wheel", sched_time_wheel, pkt_v4, test_timewheel, 1, 0);
}

void test2() {
        BPF_PROG_TEST_RUNNER("test sched_time_wheel", sched_time_wheel, pkt_v4, test_timewheel2, 1, 0);
}

int main() {
        test1();
        test2();
}