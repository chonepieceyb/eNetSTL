#include "common.h"
#include "bpf_skel/test_crc_hash.skel.h"
#include <bpf/libbpf.h>

#define XDP_IF "ens4np0"

int __callback_load(struct test_crc_hash *skel)
{
	return 0;
}

int main()
{
	BPF_XDP_SKEL_LOADER_WITH_CALLBACK(test_crc_hash, XDP_IF,
					  xdp_main, __callback_load,
					  XDP_FLAGS_DRV_MODE)
}
