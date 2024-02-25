#include <linux/module.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/bpf_mem_alloc.h>
#include <linux/btf.h>

#include "../bpf_hash_alg_simd/crc.h"

#define SK_NITRO_UPDATE_PROB_PERCENT 10
#include "geo_sampling_pool.h"

#define GEO_SAMPLING_MASK (MAX_GEOSAMPLING_SIZE - 1)

extern int register_btf_kfunc_id_set(enum bpf_prog_type prog_type,
				     const struct btf_kfunc_id_set *kset);
extern void bpf_map_area_free(void *area);
extern void *bpf_map_area_alloc(u64 size, int numa_node);

typedef typeof(GEO_SAMPLING_POOL[0][0]) geo_cnt_t;

struct geo_sampling_ctx {
	geo_cnt_t cnt;
	u32 geo_sampling_idx ____cacheline_aligned;
	geo_cnt_t (*pool)[MAX_GEOSAMPLING_SIZE] ____cacheline_aligned;
};

static typeof(GEO_SAMPLING_POOL[0]) empty_geo_cnts = { 0 };

static struct bpf_mem_alloc geo_sampling_ctx_ma;

static struct geo_sampling_ctx __percpu *_ctx;

static void init_geo_sampling_pool(struct geo_sampling_ctx *ctx, int cpu)
{
	/*init*/
	if (cpu >= ONLINE_CPU_NUM) {
		/*TODO: currently we only provide online cpu's data*/
		ctx->pool = &empty_geo_cnts;
	} else {
		ctx->pool = GEO_SAMPLING_POOL + cpu;
	}
	ctx->geo_sampling_idx = 0;
	ctx->cnt = (*ctx->pool)[0];
}

__bpf_kfunc struct geo_sampling_ctx *bpf_geo_sampling_ctx_new(void)
{
	struct geo_sampling_ctx *ctx;

	ctx = _ctx;
	if (ctx == NULL) {
		pr_err("bpf_random_base_alg: _ctx not initialized yet\n");
		ctx = ERR_PTR(-EFAULT);
		goto out;
	}

out:
	return ctx;
}
EXPORT_SYMBOL_GPL(bpf_geo_sampling_ctx_new);

__bpf_kfunc void bpf_geo_sampling_ctx_free(struct geo_sampling_ctx *ctx)
{
	pr_debug("bpf_random_base_alg: %s is not required\n", __func__);
}
EXPORT_SYMBOL_GPL(bpf_geo_sampling_ctx_free);

__bpf_kfunc bool bpf_geo_sampling_should_do(struct geo_sampling_ctx *ctx)
{
	u32 geo_value_idx;

	ctx = this_cpu_ptr(ctx);

	if (ctx->cnt > 0) {
		ctx->cnt--;
		return false;
	}

	geo_value_idx = (ctx->geo_sampling_idx + 1) & GEO_SAMPLING_MASK;
	ctx->geo_sampling_idx = geo_value_idx;
	ctx->cnt = (*ctx->pool)[geo_value_idx];

	return true;
}
EXPORT_SYMBOL_GPL(bpf_geo_sampling_should_do);

__bpf_kfunc geo_cnt_t bpf_geo_sampling_gen_geo_cnt(struct geo_sampling_ctx *ctx)
{
	u32 geo_value_idx;

	ctx = this_cpu_ptr(ctx);

	geo_value_idx = (ctx->geo_sampling_idx + 1) & GEO_SAMPLING_MASK;
	ctx->geo_sampling_idx = geo_value_idx;
	return (*ctx->pool)[geo_value_idx];
}
EXPORT_SYMBOL_GPL(bpf_geo_sampling_gen_geo_cnt);

/* Workaround for "kernel btf id 123456 is not a function" errors */
__bpf_kfunc uint32_t bpf_crc32c_sse(const void *data, uint32_t data__sz,
				    uint32_t init_val)
{
	return crc32c(data, data__sz, init_val);
}
EXPORT_SYMBOL_GPL(bpf_crc32c_sse);

BTF_SET8_START(bpf_random_base_alg_kfunc_ids)
BTF_ID_FLAGS(func, bpf_geo_sampling_ctx_new, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_geo_sampling_ctx_free, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_geo_sampling_should_do)
BTF_ID_FLAGS(func, bpf_geo_sampling_gen_geo_cnt)
BTF_ID_FLAGS(func, bpf_crc32c_sse)
BTF_SET8_END(bpf_random_base_alg_kfunc_ids)

BTF_ID_LIST(bpf_random_base_alg_dtor_ids)
BTF_ID(struct, geo_sampling_ctx)
BTF_ID(func, bpf_geo_sampling_ctx_free)

static const struct btf_kfunc_id_set bpf_random_base_alg_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_random_base_alg_kfunc_ids,
};

static int kfunc_init(void)
{
	int ret = 0;
	const struct btf_id_dtor_kfunc bpf_random_base_alg_dtors[] = {
		{
			.btf_id = bpf_random_base_alg_dtor_ids[0],
			.kfunc_btf_id = bpf_random_base_alg_dtor_ids[1],
		},
	};

	if ((ret = register_btf_id_dtor_kfuncs(
		     bpf_random_base_alg_dtors,
		     ARRAY_SIZE(bpf_random_base_alg_dtors), THIS_MODULE)) < 0) {
		pr_err("bpf_random_base_alg: failed to register kfunc dtors: %d\n",
		       ret);
	}

	if ((ret = register_btf_kfunc_id_set(
		     BPF_PROG_TYPE_XDP, &bpf_random_base_alg_kfunc_set)) < 0) {
		pr_err("bpf_random_base_alg: failed to register kfunc set: %d\n",
		       ret);
		return ret;
	}

	return ret;
}

static int mem_alloc_init(void)
{
	int ret;

	preempt_disable();
	ret = bpf_mem_alloc_init(&geo_sampling_ctx_ma,
				 sizeof(struct geo_sampling_ctx), true);
	preempt_enable();

	return ret;
}

static void mem_alloc_destroy(void)
{
	bpf_mem_alloc_destroy(&geo_sampling_ctx_ma);
}

static int __geo_sampling_ctx_init(void)
{
	struct geo_sampling_ctx *ctx;
	int ret = 0, cpu;

	ctx = alloc_percpu_gfp(typeof(*ctx), GFP_KERNEL | __GFP_ZERO);
	if (ctx == NULL) {
		pr_err("bpf_random_base_alg: failed to alloc geo sampling ctx\n");
		ret = -ENOMEM;
		goto out;
	}

	for_each_possible_cpu(cpu) {
		init_geo_sampling_pool(per_cpu_ptr(ctx, cpu), cpu);
	}

	_ctx = ctx;

out:
	return ret;
}

static void __geo_sampling_ctx_cleanup(void)
{
	struct geo_sampling_ctx *ctx;

	ctx = _ctx;
	if (ctx == NULL) {
		pr_err("bpf_random_base_alg: _ctx not initialized yet (on free)\n");
		goto out;
	}

	free_percpu(ctx);
	_ctx = NULL;

out:
	return;
}

static int __init bpf_random_base_alg_init(void)
{
	int ret;

	if ((ret = kfunc_init()) < 0) {
		pr_err("bpf_random_base_alg: failed to init kfunc: %d\n", ret);
		return ret;
	}

	if ((ret = mem_alloc_init()) < 0) {
		pr_err("bpf_random_base_alg: failed to init mem alloc: %d\n",
		       ret);
		return ret;
	}

	if ((ret = __geo_sampling_ctx_init()) < 0) {
		pr_err("bpf_random_base_alg: failed to init geo sampling ctx: %d\n",
		       ret);
	}

	pr_info("bpf_random_base_alg: initialized\n");
	return 0;
}

static void __exit bpf_random_base_alg_exit(void)
{
	__geo_sampling_ctx_cleanup();
	mem_alloc_destroy();

	pr_info("bpf_random_base_alg: exiting\n");
}

/* Register module functions */
module_init(bpf_random_base_alg_init);
module_exit(bpf_random_base_alg_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yang Hanlin");
MODULE_DESCRIPTION("");
MODULE_VERSION("0.0.1");
