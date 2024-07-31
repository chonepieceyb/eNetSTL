#include "../common.h"
#include "../bpf_skel/hypercom_sk_cm2_base.skel.h"
#include "../bpf_skel/hypercom_heavy_keeper_ext.skel.h"
#include "../test_helpers.h"

#define XDP_IF "ens2f0"

struct hypercom_heavy_keeper_ext *load_st_ops(void)
{
	BPF_MOD_LOAD_STRUCT_OPS(hypercom_heavy_keeper_ext, hash_ops,
				"hash_mod_struct_ops");
}

int main()
{
	BPF_MOD_CLEAR_STRUCT_OPS(hypercom_heavy_keeper_ext,
				 "hash_mod_struct_ops")

	struct hypercom_heavy_keeper_ext *ext_skel = load_st_ops();
	if (ext_skel == NULL) {
		return 1;
	}
	hypercom_heavy_keeper_ext__destroy(ext_skel);

	BPF_XDP_SKEL_LOADER(hypercom_sk_cm2_base, XDP_IF, xdp_main,
			    XDP_FLAGS_DRV_MODE)
}
