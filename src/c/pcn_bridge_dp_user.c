#include "common.h"
#include "bpf_skel/pcn_bridge_dp.skel.h"
#include <endian.h>
#include <netinet/in.h>
#include <stdio.h>

typedef uint32_t u32;

struct fwd_entry {
  u32 timestamp;
  u32 port;
} __attribute__((packed, aligned(8)));

static int callback_load(struct pcn_bridge_dp *skel)
{ 
  struct bpf_map *fwdtable = skel->maps.fwdtable;
  struct fwd_entry value = {
    .timestamp = 0x01000000,
    .port = 1
  };

  //  00:15:4d:13:72:80 dst
  __be64 key = 0x8072134d1500;
  for(int i=0;i<8;i++){
    printf("mac dst:%hhx\n", ((char *)&key)[i]);
  }
  printf("key: %llu\n", key);
  int res = bpf_map__update_elem(fwdtable, &key, sizeof(__be64), &value,sizeof(struct fwd_entry), BPF_ANY);
  printf("add res %d\n", res);
	return 0;
}

int main()
{
    BPF_XDP_SKEL_LOADER_WITH_CALLBACK(pcn_bridge_dp, "ens4np0", xdp_main, callback_load, XDP_FLAGS_DRV_MODE)
}