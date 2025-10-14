// module.c
// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>

extern int  simdnn_kfunc_register(void);
extern void simdnn_kfunc_unregister(void);

extern int simdnn_lkm_register(void);
extern void simdnn_lkm_unregister(void);

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
        return ret;
    }

    pr_info("simdnn: module loaded\n");
    return 0;
}

static void __exit simdnn_module_exit(void)
{
    simdnn_lkm_unregister();
    pr_info("simdnn: module unloaded\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bing Yang & Xinshu Wang");
MODULE_DESCRIPTION("SimdNN kernel module");
MODULE_VERSION("0.1");

module_init(simdnn_module_init);
module_exit(simdnn_module_exit);
