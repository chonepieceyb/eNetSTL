#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "test_helpers.h"
#include "bpf_skel/simdnn.bpf.skel.h"

static int run_smoke_test(void)
{
    struct ipv4_packet test_pkt = {
        .eth.h_proto   = __bpf_constant_htons(ETH_P_IP),
        .iph.ihl       = 5,
        .iph.protocol  = IPPROTO_TCP,
        .iph.tot_len   = __bpf_constant_htons(MAGIC_BYTES),
        .tcp.urg_ptr   = 123,
        .tcp.doff      = 5,
        .tcp.source    = htons(80),
        .tcp.dest      = htons(8080),
    };

    // 期望 XDP_PASS = 2；repeat=1，避免触发复杂路径
    BPF_PROG_TEST_RUNNER(
        "test_xdp_simdnn",
        simdnn_bpf,
        test_pkt,
        xdp_simdnn_main,
        1,
        XDP_PASS
    );
}

int main(void)
{
    printf("=== Testing SimdNN XDP Program ===\n");
    printf("Running BPF_PROG_TEST_RUNNER for xdp_simdnn_main...\n");

    int rc = run_smoke_test();         // 宏在这里“return 子函数”
    if (rc == 0) {
        printf("✓ BPF_PROG_TEST_RUNNER completed successfully\n");
        printf("✓ XDP program returned XDP_PASS\n");
        return 0;
    } else {
        printf("✗ Test failed, rc=%d (see messages above)\n", rc);
        return 1;
    }
}
