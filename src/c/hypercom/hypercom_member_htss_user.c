#include "../common.h" 
#include "../bpf_skel/hypercom_member_htss.skel.h"
#include "../test_helpers.h"

void test() {
	BPF_PROG_TEST_RUNNER("hypercom_member_htss", hypercom_member_htss, pkt_v4, test_htss, 1, XDP_PASS);
}
int main() {
	BPF_XDP_SKEL_LOADER(hypercom_member_htss, "ens4np0", xdp_main, XDP_FLAGS_DRV_MODE)
	// test();
	// return 0;
}