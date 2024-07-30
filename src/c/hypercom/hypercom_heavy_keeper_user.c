#include "../common.h"
#include "../bpf_skel/hypercom_sk_cm2_base.skel.h"
#include "../bpf_skel/hypercom_heavy_keeper_ext.skel.h"
#include "../test_helpers.h"

struct hypercom_heavy_keeper_ext *load_st_ops(void)
{
	BPF_MOD_LOAD_STRUCT_OPS(hypercom_heavy_keeper_ext, hash_ops,
				"hash_mod_struct_ops");
}

void test_run()
{
	BPF_PROG_TEST_RUNNER("test hash_mod_struct_ops", hypercom_sk_cm2_base,
			     pkt_v4, xdp_main, 1, 1);
}

/* FIXME: Attach to real XDP hookpoint */
void test()
{
	struct hypercom_heavy_keeper_ext *skel;
	skel = load_st_ops();
	if (skel == NULL)
		return;
	test_run();
	int key = 0;
	bpf_map__delete_elem(skel->maps.hash_ops, &key, sizeof(key), 0);
	hypercom_heavy_keeper_ext__destroy(skel);
}

int main()
{
	test();
}
