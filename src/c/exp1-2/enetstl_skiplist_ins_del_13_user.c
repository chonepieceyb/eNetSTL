#include "../common.h"
#include "../config.h"
#include "../config.h"
#include "../bpf_skel/enetstl_skiplist_ins_del_13.skel.h"

int main()
{
	BPF_XDP_SKEL_LOADER(enetstl_skiplist_ins_del_13, XDP_IF, xdp_main,
			    XDP_FLAGS_DRV_MODE)
}
