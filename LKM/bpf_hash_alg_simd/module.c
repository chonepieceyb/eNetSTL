#include <linux/bpf.h>
#include <linux/module.h>
#include <linux/printk.h>

// This macro is required to include <immintrin.h> in the kernel
#define _MM_MALLOC_H_INCLUDED
#include <immintrin.h>

#include "crc.h"

extern int register_btf_kfunc_id_set(enum bpf_prog_type prog_type,
				     const struct btf_kfunc_id_set *kset);

__bpf_kfunc uint32_t bpf_crc32c_sse(const void *data, uint32_t data__sz,
				    uint32_t init_val)
{
	return crc32c(data, data__sz, init_val);
}
EXPORT_SYMBOL_GPL(bpf_crc32c_sse);

BTF_SET8_START(bpf_hash_alg_simd_kfunc_ids)
BTF_ID_FLAGS(func, bpf_crc32c_sse)
BTF_SET8_END(bpf_hash_alg_simd_kfunc_ids)

static const struct btf_kfunc_id_set bpf_hash_alg_simd_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_hash_alg_simd_kfunc_ids,
};

static int __init bpf_hash_alg_simd_init(void)
{
	int ret;

	if ((ret = register_btf_kfunc_id_set(
		     BPF_PROG_TYPE_XDP, &bpf_hash_alg_simd_kfunc_set)) < 0) {
		pr_err("bpf_hash_alg_simd: failed to register kfunc set: %d\n",
		       ret);
		return ret;
	}

	pr_info("bpf_hash_alg_simd: initialized\n");
	return 0;
}

static void __exit bpf_hash_alg_simd_exit(void)
{
	pr_info("bpf_hash_alg_simd: exiting\n");
}

/* Register module functions */
module_init(bpf_hash_alg_simd_init);
module_exit(bpf_hash_alg_simd_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yang Hanlin");
MODULE_DESCRIPTION("Hashing algorithm kfuncs accelerated using SIMD");
MODULE_VERSION("0.0.1");
