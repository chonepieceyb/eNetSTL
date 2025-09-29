#include "../common.h"
#include "../config.h"
#include "../config.h"
#include "../bpf_skel/enetstl_skiplist_lookup_14.skel.h"

int main()
{
	BPF_XDP_SKEL_LOADER(enetstl_skiplist_lookup_14, XDP_IF, xdp_main,
			    XDP_MODE)
}
