#include "common.h"
#include "bpf_skel/pcn_lbdsr_dp.skel.h"

#define KEY_RANGE 64
static int callback_load(struct pcn_lbdsr_dp *skel)
{
	struct bpf_map *sessions_table = skel->maps.sessions_table;
	struct bpf_map *config_table = skel->maps.config_table;

	__u32 key_zero = 0;
	__u32 key_one = 1;
	__u32 key_two = 2;
	__be64 value_two = 2;
	__be64 backend_mac_1 = 0x112233332211;
	__be64 backend_mac_2 = 0x111111111111;
	// set total number of backend server
	bpf_map__update_elem(config_table, &key_zero, sizeof(__u32), &value_two,
			     sizeof(__be64), BPF_ANY);
	bpf_map__update_elem(config_table, &key_one, sizeof(__u32), &backend_mac_1,
			     sizeof(__be64), BPF_ANY);
	bpf_map__update_elem(config_table, &key_two, sizeof(__u32), &backend_mac_2,
			     sizeof(__be64), BPF_ANY);
	//
	
	return 0;
}

int main()
{
	BPF_XDP_SKEL_LOADER_WITH_CALLBACK(pcn_lbdsr_dp, "ens4np0", xdp_main,
					  callback_load, XDP_FLAGS_DRV_MODE)
}
