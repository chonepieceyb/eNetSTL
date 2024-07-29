#include <linux/spinlock_types.h>
#include <linux/bitops.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>

#include "crc.h"
#include "fasthash_simd.h"
#include "xxhash_simd.h"
#include "hash_callback.h"

struct pkt_5tuple {
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	uint8_t proto;
} __attribute__((packed));

extern int register_btf_kfunc_id_set(enum bpf_prog_type prog_type,
				     const struct btf_kfunc_id_set *kset);

static struct hash_callback_ops *callback_ops;
static DEFINE_SPINLOCK(callback_ops_lock);

static int empty_callback(void *ctx, int i, u32 hash)
{
	return 0;
}
DEFINE_STATIC_CALL_RET0(bpf_hash_alg_simd_callback, empty_callback);

static inline int callback(void *ctx, int i, u32 hash)
{
	return static_call(bpf_hash_alg_simd_callback)(ctx, i, hash);
}

int hash_callback_register(struct hash_callback_ops *ops)
{
	int ret = 0;

	if (ops == NULL || ops->owner == NULL || ops->callback == NULL) {
		pr_err("bpf_hash_alg_simd: invalid ops, owner or callback\n");
		ret = -EINVAL;
		goto err;
	}

	spin_lock(&callback_ops_lock);

	if (callback_ops) {
		pr_err("bpf_hash_alg_simd: callback already registered\n");
		ret = -EEXIST;
		goto err_unlock;
	}
	if (!bpf_try_module_get(ops, ops->owner)) {
		pr_err("bpf_hash_alg_simd: failed to get BPF module\b");
		ret = -ENODEV;
		goto err_unlock;
	}
	static_call_update(bpf_hash_alg_simd_callback, ops->callback);
	callback_ops = ops;

err_unlock:
	spin_unlock(&callback_ops_lock);
err:
	return ret;
}
EXPORT_SYMBOL_GPL(hash_callback_register);

void hash_callback_unregister(struct hash_callback_ops *ops)
{
	if (ops == NULL || ops->owner == NULL) {
		pr_warn("bpf_hash_alg_simd: invalid ops or owner; ignoring\n");
		return;
	}

	spin_lock(&callback_ops_lock);

	callback_ops = NULL;
	static_call_update(bpf_hash_alg_simd_callback, empty_callback);
	bpf_module_put(ops, ops->owner);

	spin_unlock(&callback_ops_lock);
}
EXPORT_SYMBOL_GPL(hash_callback_unregister);

__bpf_kfunc void bpf_xxh32_avx2_pkt5(const struct pkt_5tuple *buf,
				     const u32 *seeds, u32 *dest)
{
	__m256i seeds_vec = _mm256_loadu_si256((const __m256i_u *)seeds);
	__m256i dest_vec = xxh32_avx2_pkt5(buf, &seeds_vec);
	_mm256_storeu_si256((__m256i_u *)dest, dest_vec);
}
EXPORT_SYMBOL_GPL(bpf_xxh32_avx2_pkt5);

__bpf_kfunc void bpf_xxh32_avx2_pkt5_pkts(const u32 *bytes, const u32 seed,
					  u32 *dest)
{
	__m256i b0_vec = _mm256_loadu_si256((const __m256i_u *)bytes),
		b1_vec = _mm256_loadu_si256((const __m256i_u *)bytes + 8),
		b2_vec = _mm256_loadu_si256((const __m256i_u *)bytes + 16),
		b3_vec = _mm256_loadu_si256((const __m256i_u *)bytes + 24);
	__m256i dest_vec =
		xxh32_avx2_pkt5_pkts(&b0_vec, &b1_vec, &b2_vec, &b3_vec, seed);
	_mm256_storeu_si256((__m256i_u *)dest, dest_vec);
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

__bpf_kfunc void
bpf_fasthash32_alt_avx2_pkt5_with_callback(const struct pkt_5tuple *buf,
					   const u32 *seeds, void *ctx,
					   size_t ctx__sz)
{
	__m256i seeds_vec = _mm256_loadu_si256((const __m256i_u *)seeds);

	const __m256i hh = _fasthash64_avx2_pkt5(buf, &seeds_vec);
	const u32 *hashes = (const u32 *)&hh;

	for (int i = 0; i < 8; ++i) {
		if (callback(ctx, i, hashes[i]) != 0) {
			break;
		}
	}
}
EXPORT_SYMBOL_GPL(bpf_fasthash32_alt_avx2_pkt5_with_callback);

__bpf_kfunc uint32_t bpf_crc32c_sse(const void *data, uint32_t data__sz,
				    uint32_t init_val)
{
	return crc32c(data, data__sz, init_val);
}
EXPORT_SYMBOL_GPL(bpf_crc32c_sse);

__bpf_kfunc void bpf_kernel_fpu_begin(void)
{
	kernel_fpu_begin();
}
EXPORT_SYMBOL_GPL(bpf_kernel_fpu_begin);

__bpf_kfunc void bpf_kernel_fpu_end(void)
{
	kernel_fpu_end();
}
EXPORT_SYMBOL_GPL(bpf_kernel_fpu_end);

__bpf_kfunc void bpf_mm256_xor_si256(u8 *dest, const u8 *lhs, const u8 *rhs)
{
	__m256i lhs_vec = _mm256_loadu_si256((const __m256i_u *)lhs),
		rhs_vec = _mm256_loadu_si256((const __m256i_u *)rhs);
	__m256i dest_vec = _mm256_xor_si256(lhs_vec, rhs_vec);
	_mm256_storeu_si256((__m256i_u *)dest, dest_vec);
}
EXPORT_SYMBOL_GPL(bpf_mm256_xor_si256);

__bpf_kfunc void bpf_mm256_set1_epi64x(s64 *dest, s64 a)
{
	__m256i dest_vec = _mm256_set1_epi64x(a);
	_mm256_storeu_si256((__m256i_u *)dest, dest_vec);
}
EXPORT_SYMBOL_GPL(bpf_mm256_set1_epi64x);

__bpf_kfunc void bpf_mm256_srli_epi64(s64 *dest, const s64 *lhs, int rhs)
{
	__m256i lhs_vec = _mm256_loadu_si256((const __m256i_u *)lhs);
	__m256i dest_vec = _mm256_srli_epi64(lhs_vec, rhs);
	_mm256_storeu_si256((__m256i_u *)dest, dest_vec);
}
EXPORT_SYMBOL_GPL(bpf_mm256_srli_epi64);

__bpf_kfunc void bpf_mm256_mul_epu32(u32 *dest, const u32 *lhs, const u32 *rhs)
{
	__m256i lhs_vec = _mm256_loadu_si256((const __m256i_u *)lhs),
		rhs_vec = _mm256_loadu_si256((const __m256i_u *)rhs);
	__m256i dest_vec = _mm256_mul_epu32(lhs_vec, rhs_vec);
	_mm256_storeu_si256((__m256i_u *)dest, dest_vec);
}
EXPORT_SYMBOL_GPL(bpf_mm256_mul_epu32);

__bpf_kfunc void bpf_mm256_and_si256(u8 *dest, const u8 *lhs, const u8 *rhs)
{
	__m256i lhs_vec = _mm256_loadu_si256((const __m256i_u *)lhs),
		rhs_vec = _mm256_loadu_si256((const __m256i_u *)rhs);
	__m256i dest_vec = _mm256_and_si256(lhs_vec, rhs_vec);
	_mm256_storeu_si256((__m256i_u *)dest, dest_vec);
}
EXPORT_SYMBOL_GPL(bpf_mm256_and_si256);

__bpf_kfunc void bpf_mm256_mullo_epi32(s32 *dest, const s32 *lhs,
				       const s32 *rhs)
{
	__m256i lhs_vec = _mm256_loadu_si256((const __m256i_u *)lhs),
		rhs_vec = _mm256_loadu_si256((const __m256i_u *)rhs);
	__m256i dest_vec = _mm256_mullo_epi32(lhs_vec, rhs_vec);
	_mm256_storeu_si256((__m256i_u *)dest, dest_vec);
}
EXPORT_SYMBOL_GPL(bpf_mm256_mullo_epi32);

__bpf_kfunc void bpf_mm256_slli_si256_4(u8 *dest, const u8 *lhs)
{
	__m256i lhs_vec = _mm256_loadu_si256((const __m256i_u *)lhs);
	__m256i dest_vec = _mm256_slli_si256(lhs_vec, 4);
	_mm256_storeu_si256((__m256i_u *)dest, dest_vec);
}
EXPORT_SYMBOL_GPL(bpf_mm256_slli_si256_4);

__bpf_kfunc void bpf_mm256_add_epi32(s32 *dest, const s32 *lhs, const s32 *rhs)
{
	__m256i lhs_vec = _mm256_loadu_si256((const __m256i_u *)lhs),
		rhs_vec = _mm256_loadu_si256((const __m256i_u *)rhs);
	__m256i dest_vec = _mm256_add_epi32(lhs_vec, rhs_vec);
	_mm256_storeu_si256((__m256i_u *)dest, dest_vec);
}
EXPORT_SYMBOL_GPL(bpf_mm256_add_epi32);

BTF_SET8_START(bpf_hash_alg_simd_kfunc_ids)
BTF_ID_FLAGS(func, bpf_xxh32_avx2_pkt5)
BTF_ID_FLAGS(func, bpf_xxh32_avx2_pkt5_pkts)
BTF_ID_FLAGS(func, bpf_fasthash32_avx2)
BTF_ID_FLAGS(func, bpf_fasthash32_alt_avx2)
BTF_ID_FLAGS(func, bpf_fasthash32_alt_avx2_pkt5)
BTF_ID_FLAGS(func, bpf_fasthash32_alt_avx2_pkt5_with_callback)
BTF_ID_FLAGS(func, bpf_crc32c_sse)
BTF_ID_FLAGS(func, bpf_kernel_fpu_begin)
BTF_ID_FLAGS(func, bpf_kernel_fpu_end)
BTF_ID_FLAGS(func, bpf_mm256_xor_si256)
BTF_ID_FLAGS(func, bpf_mm256_set1_epi64x)
BTF_ID_FLAGS(func, bpf_mm256_srli_epi64)
BTF_ID_FLAGS(func, bpf_mm256_mul_epu32)
BTF_ID_FLAGS(func, bpf_mm256_and_si256)
BTF_ID_FLAGS(func, bpf_mm256_mullo_epi32)
BTF_ID_FLAGS(func, bpf_mm256_slli_si256_4)
BTF_ID_FLAGS(func, bpf_mm256_add_epi32)
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
