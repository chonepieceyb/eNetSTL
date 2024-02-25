#include "common.h"

#include "bpf_skel/test_hash_pipe.skel.h"

#define XDP_IF "ens4np0"

int main()
{
	BPF_XDP_SKEL_LOADER(test_hash_pipe, XDP_IF, xdp_test_hash_pipe,
			    XDP_FLAGS_DRV_MODE)
}
