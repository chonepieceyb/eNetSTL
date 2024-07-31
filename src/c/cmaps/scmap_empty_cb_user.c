#include "../common.h"
#include "../bpf_skel/scmap_empty_cb_base.skel.h"
#include "../bpf_skel/scmap_empty_cb_ext.skel.h"
#include "../test_helpers.h"

#define XDP_IF "ens2f0"

struct scmap_empty_cb_ext *load_st_ops(void)
{
	BPF_MOD_LOAD_STRUCT_OPS(scmap_empty_cb_ext, empty_cb_ops,
				"empty_scmap_struct_ops");
}

int main()
{
	BPF_MOD_CLEAR_STRUCT_OPS(scmap_empty_cb_ext, "empty_scmap_struct_ops");

	struct scmap_empty_cb_ext *ext_skel = load_st_ops();
	if (ext_skel == NULL) {
		return 1;
	}
	scmap_empty_cb_ext__destroy(ext_skel);

	BPF_XDP_SKEL_LOADER(scmap_empty_cb_base, XDP_IF, xdp_main,
			    XDP_FLAGS_DRV_MODE)
}
