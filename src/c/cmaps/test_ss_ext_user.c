#include "../common.h" 
#include <stdio.h>
#include <assert.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "../bpf_skel/ss_ext_test.skel.h"
#include <net/if.h>
#include <linux/if_link.h>
#include "../test_helpers.h"

void test() {
        BPF_PROG_TEST_RUNNER("ss_ext_test", ss_ext_test, pkt_v4, xdp_main, 10, XDP_PASS);
}

int main() {
        test();
}