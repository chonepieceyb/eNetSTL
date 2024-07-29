#include "common.h"
#include "bpf_skel/test_hash_mod_struct_ops.skel.h"
#include "test_helpers.h"

void test()
{
	BPF_PROG_TEST_RUNNER("test hash_mod_struct_ops",
			     test_hash_mod_struct_ops, pkt_v4, xdp_main, 1,
			     XDP_PASS);
}

int main()
{
	test();
}
