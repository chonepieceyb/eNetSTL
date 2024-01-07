#include <linux/bitops.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>

#include "crc.h"
#include "fasthash_simd.h"
#include "xxhash_simd.h"

struct pkt_5tuple {
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	uint8_t proto;
} __attribute__((packed));

extern int register_btf_kfunc_id_set(enum bpf_prog_type prog_type,
				     const struct btf_kfunc_id_set *kset);

__bpf_kfunc void bpf_xxh32_avx2_pkt5(const struct pkt_5tuple *buf,
				     const u32 *seeds, u32 *dest)
{
	*(__m256i *)dest = xxh32_avx2_pkt5(buf, (const __m256i *)seeds);
}
EXPORT_SYMBOL_GPL(bpf_xxh32_avx2_pkt5);

__bpf_kfunc void bpf_xxh32_avx2_pkt5_pkts(const u32 *bytes, const u32 seed,
					  u32 *dest)
{
	*(__m256i *)dest = xxh32_avx2_pkt5_pkts(
		(const __m256i *)bytes, (const __m256i *)bytes + 8,
		(const __m256i *)bytes + 16, (const __m256i *)bytes + 24, seed);
}
EXPORT_SYMBOL_GPL(bpf_xxh32_avx2_pkt5_pkts);

__bpf_kfunc void bpf_fasthash32_avx2(const void *buf, size_t buf__sz,
				     const u32 *seeds, u32 *dest)
{
	fasthash32_avx2(buf, buf__sz, seeds, dest);
}
EXPORT_SYMBOL_GPL(bpf_fasthash32_avx2);

__bpf_kfunc void bpf_fasthash32_alt_avx2(const void *buf, size_t buf__sz,
					 const u32 *seeds, u32 *dest)
{
	fasthash32_alt_avx2(buf, buf__sz, seeds, dest);
}
EXPORT_SYMBOL_GPL(bpf_fasthash32_alt_avx2);

__bpf_kfunc void bpf_fasthash32_alt_avx2_pkt5(const struct pkt_5tuple *buf,
					      const u32 *seeds, u32 *dest)
{
	fasthash32_alt_avx2_pkt5(buf, seeds, dest);
}
EXPORT_SYMBOL_GPL(bpf_fasthash32_alt_avx2_pkt5);

__bpf_kfunc uint32_t bpf_crc32c_sse(const void *data, uint32_t data__sz,
				    uint32_t init_val)
{
	return crc32c(data, data__sz, init_val);
}
EXPORT_SYMBOL_GPL(bpf_crc32c_sse);

BTF_SET8_START(bpf_hash_alg_simd_kfunc_ids)
BTF_ID_FLAGS(func, bpf_xxh32_avx2_pkt5)
BTF_ID_FLAGS(func, bpf_xxh32_avx2_pkt5_pkts)
BTF_ID_FLAGS(func, bpf_fasthash32_avx2)
BTF_ID_FLAGS(func, bpf_fasthash32_alt_avx2)
BTF_ID_FLAGS(func, bpf_fasthash32_alt_avx2_pkt5)
BTF_ID_FLAGS(func, bpf_crc32c_sse)
BTF_SET8_END(bpf_hash_alg_simd_kfunc_ids)

static const struct btf_kfunc_id_set bpf_hash_alg_simd_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_hash_alg_simd_kfunc_ids,
};

static int register_kfuncs(void)
{
	int ret;
	if ((ret = register_btf_kfunc_id_set(
		     BPF_PROG_TYPE_XDP, &bpf_hash_alg_simd_kfunc_set)) != 0) {
		return ret;
	}

	return 0;
}

static int initialize_hashes(void)
{
	xxh_init();
	fasthash_init();

	return 0;
}

static int __init bpf_hash_alg_simd_init(void)
{
	int ret;

	if ((ret = register_kfuncs()) != 0) {
		pr_err("bpf_hash_alg_simd: failed to register kfunc set: %d\n",
		       ret);
		return ret;
	} else {
		pr_info("bpf_hash_alg_simd: registered kfunc set\n");
	}

	if ((ret = initialize_hashes()) != 0) {
		pr_err("bpf_hash_alg_simd: failed to initialize hashes: %d\n",
		       ret);
		return ret;
	} else {
		pr_info("bpf_hash_alg_simd: initialized hashes\n");
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
MODULE_DESCRIPTION("BPF SIMD-accelerated hashing algorithm kfunc set");
MODULE_VERSION("0.0.1");
