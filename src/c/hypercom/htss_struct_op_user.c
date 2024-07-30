#include "../common.h" 
#include "../bpf_skel/htss_structop_base.skel.h"
#include "../bpf_skel/htss_structop_ext.skel.h"
#include "../test_helpers.h"

#define XDP_IF "ens2f0"

struct htss_structop_ext *load_st_ops(void)
{
        BPF_MOD_LOAD_STRUCT_OPS(htss_structop_ext, htss_struct_op, "htss_struct_ops");
}

void test_run() {
        BPF_PROG_TEST_RUNNER("test mod st demo", htss_structop_base, pkt_v4, xdp_main, 1,  0);
}

void test() {
        struct htss_structop_ext *skel;
        skel = load_st_ops();
        if (skel == NULL)
                return;
        test_run();
        int key = 0;
        bpf_map__delete_elem(skel->maps.htss_struct_op, &key, sizeof(key), 0);
        htss_structop_ext__destroy(skel);
}

int main()
{
	BPF_MOD_CLEAR_STRUCT_OPS(htss_structop_ext, "htss_struct_ops")

	// struct htss_structop_ext *ext_skel = load_st_ops();
	// if (ext_skel == NULL) {
	// 	return 1;
	// }

	// htss_structop_ext__destroy(ext_skel);
	// BPF_XDP_SKEL_LOADER(htss_structop_base, XDP_IF, xdp_main,
	// 		    XDP_FLAGS_DRV_MODE)
}
