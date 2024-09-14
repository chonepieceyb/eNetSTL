#include <linux/export.h>
#include <linux/preempt.h>
#include <linux/spinlock_types.h>
#include <linux/bitops.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>
#include <linux/filter.h>
#include "common.h"
#include "crc.h"
#include "xxhash_simd.h"
#include "hash_alg_post.h"
#include "cmp_alg.h"
#include "bkt_list.h"
#include "geo_sampling.h"

#define ADAPT_COUNTMIN 1

extern int register_btf_kfunc_id_set(enum bpf_prog_type prog_type,
				     const struct btf_kfunc_id_set *kset);

struct key_type_16 {
	char data[16];
};

__bpf_kfunc int bpf_k16_cmp_eq(const struct key_type_16 *key1,
			       const struct key_type_16 *key2)
{
	return __k16_cmp_eq(key1, sizeof(*key1), key2, sizeof(*key2));
}
EXPORT_SYMBOL_GPL(bpf_k16_cmp_eq);

__bpf_kfunc u32 bpf__find_mask_u16_avx(const u16 *arr, u16 val)
{
	return __find_mask_u16_avx(arr, val);
}
EXPORT_SYMBOL_GPL(bpf__find_mask_u16_avx);

__bpf_kfunc u32 bpf_find_u16_avx(const u16 *arr, u16 val)
{
	return __find_u16_avx(arr, val);
}
EXPORT_SYMBOL_GPL(bpf_find_u16_avx);

/*library of hashes*/
__bpf_kfunc void bpf_hash_smid_cnt_u32(const struct pkt_5tuple *buf, void *mem,
				       u64 size__sz, u32 column_shift)

{
	return hash_smid_cnt_u32(buf, (u32 *)mem, size__sz, column_shift);
}
EXPORT_SYMBOL_GPL(bpf_hash_smid_cnt_u32);

/*library of hashes*/
__bpf_kfunc uint32_t bpf_crc32c_sse(const void *data, uint32_t data__sz,
				    uint32_t init_val)
{
	return crc32c(data, data__sz, init_val);
}
EXPORT_SYMBOL_GPL(bpf_crc32c_sse);

__bpf_kfunc u32 bpf_crc32_hash(const void *key, u32 key__sz, u32 seed)
{
	return crc32c(key, key__sz, seed);
}
EXPORT_SYMBOL_GPL(bpf_crc32_hash);

__bpf_kfunc uint32_t bpf_htss_sig_cmp(const void *sigs, size_t sigs__sz,
				      __u16 tmp_sig)
{
	__u32 hitmask = _mm256_movemask_epi8((__m256i)_mm256_cmpeq_epi16(
		_mm256_load_si256((__m256i const *)sigs),
		_mm256_set1_epi16(tmp_sig)));
	return hitmask;
}
EXPORT_SYMBOL_GPL(bpf_htss_sig_cmp);

__bpf_kfunc u32 bpf_tzcnt_u32(u32 val)
{
	return __tzcnt_u32(val);
}
EXPORT_SYMBOL_GPL(bpf_tzcnt_u32);

__bpf_kfunc u64 bpf_ffs(u64 val)
{
	return __ffs(val);
}
EXPORT_SYMBOL_GPL(bpf_ffs);

struct bpf_bkt_list {
	int fd;
};

__bpf_kfunc struct bpf_bkt_list *bpf_bktlist_new(void)
{
	
	return (struct bpf_bkt_list *)bktlist_new();
}
EXPORT_SYMBOL_GPL(bpf_bktlist_new);

__bpf_kfunc void bpf_bktlist_free_preempt_disabled(struct bpf_bkt_list *bktlist)
{
	preempt_disable();
	bktlist_free((struct bkt_list *)bktlist);
	preempt_enable();
}

__bpf_kfunc void bpf_bktlist_free(struct bpf_bkt_list *bktlist)
{
	bktlist_free((struct bkt_list *)bktlist);
}
EXPORT_SYMBOL_GPL(bpf_bktlist_free);

__bpf_kfunc int bpf_bktlist_pop_front(int fd, void *val,
				      size_t size__szk, size_t slot)
{
	return bktlist_pop_front(fd, val, size__szk,
				 slot);
}
EXPORT_SYMBOL_GPL(bpf_bktlist_pop_front);

__bpf_kfunc int bpf_bktlist_push_back(int fd,
				      const void *val, size_t size__szk,
				      size_t slot)
{
	return bktlist_push_back(fd, val, size__szk,
				 slot);
}
EXPORT_SYMBOL_GPL(bpf_bktlist_push_back);

BTF_SET8_START(eNetSTL_kfunc_ids)
BTF_ID_FLAGS(func, bpf_crc32c_sse)
BTF_ID_FLAGS(func, bpf_hash_smid_cnt_u32)
BTF_ID_FLAGS(func, bpf_k16_cmp_eq)
BTF_ID_FLAGS(func, bpf__find_mask_u16_avx)
BTF_ID_FLAGS(func, bpf_find_u16_avx)
BTF_ID_FLAGS(func, bpf_crc32_hash)
BTF_ID_FLAGS(func, bpf_htss_sig_cmp)
BTF_ID_FLAGS(func, bpf_tzcnt_u32)
BTF_ID_FLAGS(func, bpf_ffs)
BTF_ID_FLAGS(func, bpf_bktlist_new, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_bktlist_free, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_bktlist_pop_front)
BTF_ID_FLAGS(func, bpf_bktlist_push_back)
BTF_ID_FLAGS(func, bpf_geo_sampling_ctx_new, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_geo_sampling_ctx_free, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_geo_sampling_should_do)
BTF_ID_FLAGS(func, bpf_geo_sampling_gen_geo_cnt)
BTF_SET8_END(eNetSTL_kfunc_ids)

BTF_ID_LIST(eNetSTL_dtor_ids)
BTF_ID(struct, bpf_bkt_list)
BTF_ID(func, bpf_bktlist_free_preempt_disabled)
BTF_ID(struct, geo_sampling_ctx)
BTF_ID(func, bpf_geo_sampling_ctx_free)

static const struct btf_kfunc_id_set eNetSTL_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &eNetSTL_kfunc_ids,
};

static int register_kfuncs(void)
{
	int ret;
	if ((ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
					     &eNetSTL_kfunc_set)) != 0) {
		return ret;
	}
	return 0;
}

static int initialize_hashes(void)
{
	xxh_init();
	hash_post_init();
	return 0;
}

static int __init eNetSTL_init(void)
{
	int ret = 0;
	const struct btf_id_dtor_kfunc eNetSTL_dtors[] = {
		{
			.btf_id = eNetSTL_dtor_ids[0],
			.kfunc_btf_id = eNetSTL_dtor_ids[1],
		},
		{
			.btf_id = eNetSTL_dtor_ids[2],
			.kfunc_btf_id = eNetSTL_dtor_ids[3],
		}
	};

	ret = ret   ?:
		      register_btf_id_dtor_kfuncs(eNetSTL_dtors,
						  ARRAY_SIZE(eNetSTL_dtors),
						  THIS_MODULE);
	ret = ret ?: register_kfuncs();
	if (ret != 0) {
		pr_err("eNetSTL: failed to register kfunc set: %d\n", ret);
		return ret;
	} else {
		pr_info("eNetSTL: registered kfunc set\n");
	}

	if ((ret = initialize_hashes()) != 0) {
		pr_err("eNetSTL: failed to initialize hashes: %d\n", ret);
		return ret;
	} else {
		pr_info("eNetSTL: initialized hashes\n");
	}

	if ((ret = init_bktlist_module()) != 0) {
		pr_err("eNetSTL: failed to initialize bkt list: %d\n", ret);
		return ret;
	} else {
		pr_info("eNetSTL: initialized bktlist\n");
	}

	if ((ret = geo_sampling_init()) != 0) {
		pr_err("eNetSTL: failed to initialize geo sampling: %d\n", ret);
		goto cleanup_bktlist;
	} else {
		pr_info("eNetSTL: initialized geo sampling\n");
	}
	
	return 0;
	
cleanup_bktlist:
	free_bktlist_module();
	return ret;
}

static void __exit eNetSTL_exit(void)
{
	geo_sampling_cleanup();
	free_bktlist_module();
	pr_info("eNetSTL: exiting\n");
}

/* Register module functions */
module_init(eNetSTL_init);
module_exit(eNetSTL_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bin Yang && Yang Hanlin && Lunqi Zhao");
MODULE_DESCRIPTION("eNetSTL Library");
MODULE_VERSION("0.0.1");