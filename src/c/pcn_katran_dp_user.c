#include "common.h"
#include "bpf_skel/pcn_katran_dp.skel.h"
#include <netinet/in.h>
#include <stdio.h>

#define CPU_NUM 40
struct vip_definition {
  __be32 vip;
  __u16 port;
  __u8 proto;
};

// result of vip's lookup
struct vip_meta {
  __u32 flags;
  __u32 vip_num;
};

struct lb_stats {
  __u64 v1;
  __u64 v2;
};

static int callback_load(struct pcn_katran_dp *skel)
{ 
  // add vip backend info
  struct vip_definition vip1 = {
    .vip = 0x6F6F6F6F,
    .port = 0x1111,
    .proto = 17
  };
  struct vip_definition vip2 = {
    .vip = 0xDEDEDEDE,
    .port = 0x2222,
    .proto = 17
  };
  struct vip_definition vip3 = {
    .vip = 0x79797979,
    .port = 0x3333,
    .proto = 17
  };
  struct vip_meta meta = {
    .flags = 1<<5, //F_LOCAL_VIP
    .vip_num = 1
  };
  struct bpf_map *vip_map = skel->maps.vip_map;
  int res = bpf_map__update_elem(vip_map, &vip1, sizeof(struct vip_definition), &meta, sizeof(struct vip_meta), BPF_ANY);
  res = bpf_map__update_elem(vip_map, &vip2, sizeof(struct vip_definition), &meta, sizeof(struct vip_meta), BPF_ANY);
  res = bpf_map__update_elem(vip_map, &vip3, sizeof(struct vip_definition), &meta, sizeof(struct vip_meta), BPF_ANY);
  printf("add res: %d\n", res);

  //add load balance stat info
  struct bpf_map *stats_map = skel->maps.stats;
  // struct lb_stats lb = {
  //   .v1 = 0,
  //   .v2 = 0
  // };
  struct lb_stats lb_percpu[CPU_NUM] = {0};
  int stat_key = 512;
  res = bpf_map__update_elem(stats_map, &stat_key, sizeof(int), &lb_percpu, sizeof(struct lb_stats) * CPU_NUM, BPF_ANY);
  printf("add res: %d\n", res);

	return 0;
}

int main()
{
    BPF_XDP_SKEL_LOADER_WITH_CALLBACK(pcn_katran_dp, "ens4np0", xdp_main, callback_load, XDP_FLAGS_DRV_MODE)
}