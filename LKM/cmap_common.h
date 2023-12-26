#ifndef __CMAP_COMMON_H
#define __CMAP_COMMON_H

#include <linux/bpf.h>
#include <linux/bpf_custom_map.h>
#include <linux/module.h> 
#include <linux/vmalloc.h>
#include <linux/slab.h>

/**********************************************************
 * ************COMMON PARTS********************************
 * *******************************************************/

extern int bpf_register_custom_map(struct bpf_custom_map_ops *cmap);
extern void bpf_unregister_custom_map(struct bpf_custom_map_ops *cmap);

#define BPF_CMAP_ENUM(_name) BPF_CMAP_##_name,

#define DECLARE_BPF_CMAP_IDS(bpf_cmap_types)			\
enum {								\
	bpf_cmap_types(BPF_CMAP_ENUM)				\
	__NR_BPF_CMAP_TYPE,					\
};

#define INIT_BPF_CMAP(_name)					\
_name.id = BPF_CMAP_##_name + (BASE_ID);	

#define INIT_BPF_CMAPS(bpf_cmap_types)				\
static __always_inline void init_cmaps_attr(void)			\
{								\
	bpf_cmap_types(INIT_BPF_CMAP)				\
}

#define BPF_CMAP_TYPE_ITEM(_name) [BPF_CMAP_##_name] = &_name,

#define BPF_CMAPS(name, bpf_cmap_types)				\
static struct bpf_custom_map_ops* name[__NR_BPF_CMAP_TYPE] = {	\
	bpf_cmap_types(BPF_CMAP_TYPE_ITEM)					\
};

#define BPF_CMAPS_SEC(cmaps_name, bpf_cmap_types)			\
DECLARE_BPF_CMAP_IDS(bpf_cmap_types)					\
INIT_BPF_CMAPS(bpf_cmap_types)					\
BPF_CMAPS(cmaps_name, bpf_cmap_types)

static void unregister_cmaps(struct bpf_custom_map_ops **cmaps, int num)
{
	int i;
	struct bpf_custom_map_ops **cmapp = cmaps;
	struct bpf_custom_map_ops *cmap;
	cmap = *cmaps;
	for (i = 0; i < num; i++) {
		cmap = *cmapp;
		bpf_unregister_custom_map(cmap);
		pr_info("unregister %s, id : %d\n", cmap->name, cmap->id);
		cmapp++;
	}

}

static int register_cmaps(struct bpf_custom_map_ops **cmaps, int num)
{
	int i, ret;
	struct bpf_custom_map_ops **cmapp = cmaps;
	struct bpf_custom_map_ops *cmap;
	for (i = 0; i < num; i++) {
		cmap = *cmapp;
		ret = bpf_register_custom_map(cmap);
		if (ret < 0) {
			pr_err("failed to reigster %s,  with id %d, err: %d\n", cmap->name, cmap->id, ret);
			break;
		}
		pr_info("register %s, id : %d\n", cmap->name, cmap->id);
		cmapp++;
	}
	/* if all cmap register success i == num a
	 * current num of success register cmap is i*/
	if (i < num) {
		pr_err("something wrong with cmap regs");
		unregister_cmaps(cmaps, i);
	}
	return ret;
}

#endif