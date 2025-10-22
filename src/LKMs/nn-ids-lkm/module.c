// module.c
// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include "nn-ids-enetstl-lkm.h"

__bpf_kfunc_start_defs();

/* ===================== kfunc for eBPF ===================== */
#include <linux/btf.h>
#include <linux/bpf.h>

/* 语义：
 *   model:          模型起始地址（BTF 类型经 verifier 约束后可安全传递）
 *   model_size__sz: 模型大小（字节）
 *   attr:           输入特征首地址（以 int* 解释）
 *   attr_size__sz:  输入特征大小（字节）
 * 返回：最终输出维度（>0），负值为错误码
 */
__bpf_kfunc int bpf_nm_inference(void *model__buf, int model_size__sz,
                                 void *attr__buf, int attr_size__sz)
{
    if (!model__buf || !attr__buf)
        return -EINVAL;
    if (model_size__sz <= 0)
        return -EINVAL;
    if (attr_size__sz <= 0 || (attr_size__sz % sizeof(int)) != 0)
        return -EINVAL;

    /* 只写回 model->output_buffer，让 BPF 端直接读取它 */
    return simdnn_analyze_and_infer(model__buf, model_size__sz,
                                    (int *)attr__buf, attr_size__sz);
}


__bpf_kfunc void relu_nm_forward(void *v__buf, int v_size__sz)
{
    //kernel_fpu_begin();
    relu_inplace_i32(v__buf, v_size__sz / sizeof(int));
    //kernel_fpu_end();
}

__bpf_kfunc int fc_nm_forward(const struct fc_layer *fc_layer,
                              void *x__buf, int x_size__sz,
                              void *y__buf, int y_size__sz)
{
    //kernel_fpu_begin();
    int ret = fc_forward_i32((const struct fc_layer *)fc_layer,
                             x__buf, x_size__sz / sizeof(int),
                             y__buf, y_size__sz / sizeof(int));
    //kernel_fpu_end();
    return ret;
}

__bpf_kfunc int fpu_begin(void)
{
    kernel_fpu_begin();
    return 0;
}

__bpf_kfunc int fpu_end(void)
{
    kernel_fpu_end();
    return 0;
}


__bpf_kfunc_end_defs();

BTF_KFUNCS_START(simdnn_kfunc_ids)
BTF_ID_FLAGS(func, bpf_nm_inference)
BTF_ID_FLAGS(func, relu_nm_forward)
BTF_ID_FLAGS(func, fc_nm_forward)
BTF_ID_FLAGS(func, fpu_begin)
BTF_ID_FLAGS(func, fpu_end)
BTF_KFUNCS_END(simdnn_kfunc_ids)

static const struct btf_kfunc_id_set simdnn_kfunc_set = {
    .owner = THIS_MODULE,
    .set = &simdnn_kfunc_ids,
};

extern int register_btf_kfunc_id_set(enum bpf_prog_type prog_type,
                                     const struct btf_kfunc_id_set *kset);

static int simdnn_kfunc_register(void)
{
    return register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &simdnn_kfunc_set);
}
static void simdnn_kfunc_unregister(void)
{
    pr_info("simdnn: kfunc unregister\n");
}

// int simdnn_lkm_register(void);
// void simdnn_lkm_unregister(void);

static int __init simdnn_module_init(void)
{
    int ret;

    pr_info("simdnn: module init\n");

    ret = simdnn_kfunc_register();
    if (ret)
    {
        pr_err("simdnn: kfunc register failed: %d\n", ret);
        return ret;
    }

    // ret = simdnn_lkm_register();

    pr_info("simdnn: module loaded\n");
    return 0;
}

static void __exit simdnn_module_exit(void)
{
    // simdnn_lkm_unregister();
    simdnn_kfunc_unregister();
    pr_info("simdnn: module unloaded\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bing Yang & Xinshu Wang");
MODULE_DESCRIPTION("SimdNN kernel module");
MODULE_VERSION("0.1");

module_init(simdnn_module_init);
module_exit(simdnn_module_exit);
