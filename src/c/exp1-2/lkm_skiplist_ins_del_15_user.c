#include "../common.h"
#include "../config.h"
#include "../config.h"
#include "../bpf_skel/lkm_skiplist_ins_del_15.skel.h"

int main()
{
	BPF_XDP_SKEL_LOADER(lkm_skiplist_ins_del_15, XDP_IF, xdp_main,
			    XDP_FLAGS_DRV_MODE)
}
