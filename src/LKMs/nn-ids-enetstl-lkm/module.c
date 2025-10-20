// module.c
// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>
#include <linux/kernel.h>

__bpf_kfunc int bpf_nm_inference(void *model, int model_size__sz,
                                 void *attr, int attr_size__sz);

BTF_SET8_START(simdnn_kfunc_ids)
BTF_ID_FLAGS(func, bpf_nm_inference)
BTF_SET8_END(simdnn_kfunc_ids)

static const struct btf_kfunc_id_set simdnn_kfunc_set = {
    .owner = THIS_MODULE,
    .set   = &simdnn_kfunc_ids,
};

extern int register_btf_kfunc_id_set(enum bpf_prog_type prog_type,
                                     const struct btf_kfunc_id_set *kset);

static int  simdnn_kfunc_register(void)
{
    return register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &simdnn_kfunc_set);
}
static void simdnn_kfunc_unregister(void)
{
    pr_info("simdnn: kfunc unregister\n");
}

int  simdnn_lkm_register(void);
void simdnn_lkm_unregister(void);

static int __init simdnn_module_init(void)
{
    int ret;

    pr_info("simdnn: module init\n");

    ret = simdnn_kfunc_register();
    if (ret) {
        pr_err("simdnn: kfunc register failed: %d\n", ret);
        return ret;
    }

    ret = simdnn_lkm_register();
    if (ret) {
        pr_err("simdnn: lkm register failed: %d\n", ret);
        simdnn_kfunc_unregister();
        return ret;
    }

    pr_info("simdnn: module loaded\n");
    return 0;
}

static void __exit simdnn_module_exit(void)
{
    simdnn_lkm_unregister();
    simdnn_kfunc_unregister();
    pr_info("simdnn: module unloaded\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bing Yang & Xinshu Wang");
MODULE_DESCRIPTION("SimdNN kernel module");
MODULE_VERSION("0.1");

module_init(simdnn_module_init);
module_exit(simdnn_module_exit);
