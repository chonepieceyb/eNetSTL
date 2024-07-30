#include "../common.h"
#include "../bpf_skel/hash_mod_struct_ops_base.skel.h"
#include "../bpf_skel/hash_mod_struct_ops_ext.skel.h"
#include "../test_helpers.h"

struct hash_mod_struct_ops_ext *load_st_ops(void)
{
	BPF_MOD_LOAD_STRUCT_OPS(hash_mod_struct_ops_ext, hash_ops,
				"hash_mod_struct_ops");
}

void test_run()
{
	BPF_PROG_TEST_RUNNER("test hash_mod_struct_ops",
			     hash_mod_struct_ops_base, pkt_v4, xdp_main, 1, 2);
}

void test()
{
	struct hash_mod_struct_ops_ext *skel;

	BPF_MOD_CLEAR_STRUCT_OPS(hash_mod_struct_ops_ext, "hash_mod_struct_ops")
	skel = load_st_ops();
	if (skel == NULL)
		return;
	test_run();
	int key = 0;
	bpf_map__delete_elem(skel->maps.hash_ops, &key, sizeof(key), 0);
	hash_mod_struct_ops_ext__destroy(skel);
}

int main()
{
	test();
}