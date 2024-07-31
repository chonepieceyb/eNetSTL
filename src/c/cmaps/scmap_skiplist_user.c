#include "../common.h"
#include "../bpf_skel/scmap_skiplist.skel.h"

// 修改这里控制变量
#define KEY_RANGE 4096

static int callback_load(struct scmap_skiplist *skel)
{
  struct bpf_map *skip_list = skel->maps.skip_list;
  //初始化skip_list，填入KEY_RANGE个元素
  for (u64 i = 0; i < KEY_RANGE; i++) {
    int res = bpf_map__update_elem(skip_list, &i, sizeof(u64), &i,
                 sizeof(u64), BPF_ANY);
  }
  printf("KEY_RANGE: %d, skip_list init finished.\n", KEY_RANGE);
  return 0;
}

int main()
{
  BPF_XDP_SKEL_LOADER_WITH_CALLBACK(scmap_skiplist, "ens2f0", xdp_main,
            callback_load, XDP_FLAGS_DRV_MODE)
}