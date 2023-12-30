#include "common.h" 
#include "bpf_skel/linked_list_test.skel.h"
#include "test_helpers.h"

void test1() {
        BPF_PROG_TEST_RUNNER("linked_list_test", linked_list_test, pkt_v4, map_list_push_pop_inmap, 1, 0);
}

void test2() {
        BPF_PROG_TEST_RUNNER("linked_list_test", linked_list_test, pkt_v4, map_list_push_pop_global, 1, 0);
}

int main() {
        test1();
        test2();
}