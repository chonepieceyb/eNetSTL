#include <linux/module.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/bpf_mem_alloc.h>
#include <linux/btf.h>

#define SK_NITRO_UPDATE_PROB_PERCENT 10
#include "geo_sampling_pool.h"

#define GEO_SAMPLING_MASK (MAX_GEOSAMPLING_SIZE - 1)

extern int register_btf_kfunc_id_set(enum bpf_prog_type prog_type,
				     const struct btf_kfunc_id_set *kset);
extern void bpf_map_area_free(void *area);
extern void *bpf_map_area_alloc(u64 size, int numa_node);

struct geo_sampling_ctx {
	u32 cnt;
	u32 geo_sampling_idx ____cacheline_aligned;
	u8 pool[MAX_GEOSAMPLING_SIZE] ____cacheline_aligned;
};

static struct bpf_mem_alloc geo_sampling_ctx_ma;

static void init_geo_sampling_pool(struct geo_sampling_ctx *ctx, int cpu)
{
	/*init*/
	ctx->geo_sampling_idx = 0;
	ctx->cnt = 0;
	if (cpu >= ONLINE_CPU_NUM) {
		/*TODO: currently we only provide online cpu's data*/
		//memset(__geo_sampling_pool, 0, sizeof(u32) * MAX_GEOSAMPLING_SIZE);
		memset(ctx->pool, 0, ARRAY_SIZE(ctx->pool));
	} else {
		memcpy(ctx->pool, GEO_SAMPLING_POOL[cpu],
		       ARRAY_SIZE(ctx->pool));
	}
}

__bpf_kfunc struct geo_sampling_ctx *bpf_geo_sampling_ctx_new(void)
{
	struct geo_sampling_ctx *ctx;

	ctx = bpf_mem_cache_alloc(&geo_sampling_ctx_ma);
	if (ctx == NULL) {
		pr_err("bpf_random_base_alg: failed to alloc geo_sampling_ctx\n");
		goto out;
	}

	init_geo_sampling_pool(ctx, smp_processor_id());

out:
	return ctx;
}
EXPORT_SYMBOL_GPL(bpf_geo_sampling_ctx_new);

__bpf_kfunc void bpf_geo_sampling_ctx_free(struct geo_sampling_ctx *ctx)
{
	bpf_mem_cache_free(&geo_sampling_ctx_ma, ctx);
}
EXPORT_SYMBOL_GPL(bpf_geo_sampling_ctx_free);

__bpf_kfunc bool bpf_geo_sampling_should_do(struct geo_sampling_ctx *ctx)
{
	uint32_t geo_value_idx = ctx->geo_sampling_idx;

	if (ctx->cnt < ctx->pool[geo_value_idx]) {
		ctx->cnt = ctx->cnt + 1;
		return false;
	}

	geo_value_idx = (geo_value_idx + 1) & GEO_SAMPLING_MASK;
	ctx->geo_sampling_idx = geo_value_idx;
	ctx->cnt = 0;

	return true;
}
EXPORT_SYMBOL_GPL(bpf_geo_sampling_should_do);

BTF_SET8_START(bpf_random_base_alg_kfunc_ids)
BTF_ID_FLAGS(func, bpf_geo_sampling_ctx_new, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_geo_sampling_ctx_free, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_geo_sampling_should_do)
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

	pr_info("bpf_random_base_alg: initialized\n");
	return 0;
}

static void __exit bpf_random_base_alg_exit(void)
{
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
