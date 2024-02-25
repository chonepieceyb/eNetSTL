#include "common.h" 
#include "bpf_skel/test_bpf_hash_alg_simd.skel.h"
#include "test_helpers.h"

void test() {
        BPF_PROG_TEST_RUNNER("test bpf_hash_alg_simd", test_bpf_hash_alg_simd, pkt_v4, xdp_main, 1, XDP_PASS);
}

int main() {
        test();
}
