#include "linux/err.h"
#include <linux/module.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/bpf_mem_alloc.h>
#include <linux/btf.h>

#include "geo_sampling.h"
#include "geo_sampling_pool.h"

#define GEO_SAMPLING_MASK (MAX_GEOSAMPLING_SIZE - 1)

extern int register_btf_kfunc_id_set(enum bpf_prog_type prog_type,
				     const struct btf_kfunc_id_set *kset);
extern void bpf_map_area_free(void *area);
extern void *bpf_map_area_alloc(u64 size, int numa_node);

typedef typeof(GEO_SAMPLING_POOL_2[0]) geo_cnt_pool_t;
typedef typeof(GEO_SAMPLING_POOL_2[0][0]) geo_cnt_t;

struct geo_sampling_ctx {
	int fd; /* currently fd is equal to update probability (in percent) */
	geo_cnt_t cnt;
	u32 geo_sampling_idx ____cacheline_aligned;
	geo_cnt_pool_t *pool ____cacheline_aligned;
};

static geo_cnt_pool_t empty_geo_cnt_pool = { 0 };

static struct geo_sampling_ctx __percpu *_ctx_2 = NULL, *_ctx_4 = NULL,
					*_ctx_6 = NULL, *_ctx_8 = NULL,
					*_ctx_10 = NULL;

static void init_geo_sampling_pool(struct geo_sampling_ctx *ctx, int fd,
				   geo_cnt_pool_t *pool, int cpu)
{
	/*init*/
	ctx->fd = fd;
	if (cpu >= ONLINE_CPU_NUM) {
		/*TODO: currently we only provide online cpu's data*/
		pr_warn("bpf_random_base_alg: no available pool for CPU %d\n",
			cpu);
		ctx->pool = &empty_geo_cnt_pool;
	} else {
		ctx->pool = pool + cpu;
	}
	ctx->geo_sampling_idx = 0;
	ctx->cnt = (*ctx->pool)[0];
}

__bpf_kfunc struct geo_sampling_ctx *bpf_geo_sampling_ctx_new(int prob_percent)
{
	struct geo_sampling_ctx *ctx = NULL;

	switch (prob_percent) {
	case 2:
		ctx = _ctx_2;
		break;
	case 4:
		ctx = _ctx_4;
		break;
	case 6:
		ctx = _ctx_6;
		break;
	case 8:
		ctx = _ctx_8;
		break;
	case 10:
		ctx = _ctx_10;
		break;
	default:
		pr_err("bpf_random_base_alg: invalid prob_percent %d\n",
		       prob_percent);
		goto out;
	}
	if (ctx == NULL) {
		pr_err("bpf_random_base_alg: _ctx not initialized yet\n");
		goto out;
	}

	ctx = this_cpu_ptr(ctx);

out:
	return ctx;
}
EXPORT_SYMBOL_GPL(bpf_geo_sampling_ctx_new);

__bpf_kfunc void bpf_geo_sampling_ctx_free(struct geo_sampling_ctx *ctx)
{
	pr_debug("bpf_random_base_alg: %s is not required\n", __func__);
}
EXPORT_SYMBOL_GPL(bpf_geo_sampling_ctx_free);

__bpf_kfunc bool bpf_geo_sampling_should_do(int fd)
{
	u32 geo_value_idx;
	struct geo_sampling_ctx *ctx;

	switch (fd) {
	case 2:
		ctx = _ctx_2;
		break;
	case 4:
		ctx = _ctx_4;
		break;
	case 6:
		ctx = _ctx_6;
		break;
	case 8:
		ctx = _ctx_8;
		break;
	case 10:
		ctx = _ctx_10;
		break;
	default:
		pr_err("bpf_random_base_alg: invalid fd %d\n", fd);
		return false;
	}

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

__bpf_kfunc geo_cnt_t bpf_geo_sampling_gen_geo_cnt(int fd)
{
	u32 geo_value_idx;
	struct geo_sampling_ctx *ctx;

	switch (fd) {
	case 2:
		ctx = _ctx_2;
		break;
	case 4:
		ctx = _ctx_4;
		break;
	case 6:
		ctx = _ctx_6;
		break;
	case 8:
		ctx = _ctx_8;
		break;
	case 10:
		ctx = _ctx_10;
		break;
	default:
		pr_err("bpf_random_base_alg: invalid fd %d\n", fd);
		return 0; /* 0 is the only invalid number in geo_cnt_t */
	}

	ctx = this_cpu_ptr(ctx);

	geo_value_idx = (ctx->geo_sampling_idx + 1) & GEO_SAMPLING_MASK;
	ctx->geo_sampling_idx = geo_value_idx;
	ctx->cnt = (*ctx->pool)[geo_value_idx];

	return ctx->cnt;
}
EXPORT_SYMBOL_GPL(bpf_geo_sampling_gen_geo_cnt);

int geo_sampling_init(void)
{
	struct geo_sampling_ctx *ctx;
	int ret = 0, cpu;

	ctx = alloc_percpu_gfp(typeof(*ctx), GFP_KERNEL | __GFP_ZERO);
	if (ctx == NULL) {
		pr_err("bpf_random_base_alg: failed to alloc geo sampling ctx\n");
		ret = -ENOMEM;
		goto err;
	}
	for_each_possible_cpu(cpu) {
		init_geo_sampling_pool(per_cpu_ptr(ctx, cpu), 2,
				       GEO_SAMPLING_POOL_2, cpu);
	}
	_ctx_2 = ctx;

	ctx = alloc_percpu_gfp(typeof(*ctx), GFP_KERNEL | __GFP_ZERO);
	if (ctx == NULL) {
		pr_err("bpf_random_base_alg: failed to alloc geo sampling ctx\n");
		ret = -ENOMEM;
		goto err;
	}
	for_each_possible_cpu(cpu) {
		init_geo_sampling_pool(per_cpu_ptr(ctx, cpu), 4,
				       GEO_SAMPLING_POOL_4, cpu);
	}
	_ctx_4 = ctx;

	ctx = alloc_percpu_gfp(typeof(*ctx), GFP_KERNEL | __GFP_ZERO);
	if (ctx == NULL) {
		pr_err("bpf_random_base_alg: failed to alloc geo sampling ctx\n");
		ret = -ENOMEM;
		goto err;
	}
	for_each_possible_cpu(cpu) {
		init_geo_sampling_pool(per_cpu_ptr(ctx, cpu), 6,
				       GEO_SAMPLING_POOL_6, cpu);
	}
	_ctx_6 = ctx;

	ctx = alloc_percpu_gfp(typeof(*ctx), GFP_KERNEL | __GFP_ZERO);
	if (ctx == NULL) {
		pr_err("bpf_random_base_alg: failed to alloc geo sampling ctx\n");
		ret = -ENOMEM;
		goto err;
	}
	for_each_possible_cpu(cpu) {
		init_geo_sampling_pool(per_cpu_ptr(ctx, cpu), 8,
				       GEO_SAMPLING_POOL_8, cpu);
	}
	_ctx_8 = ctx;

	ctx = alloc_percpu_gfp(typeof(*ctx), GFP_KERNEL | __GFP_ZERO);
	if (ctx == NULL) {
		pr_err("bpf_random_base_alg: failed to alloc geo sampling ctx\n");
		ret = -ENOMEM;
		goto err;
	}
	for_each_possible_cpu(cpu) {
		init_geo_sampling_pool(per_cpu_ptr(ctx, cpu), 10,
				       GEO_SAMPLING_POOL_10, cpu);
	}
	_ctx_10 = ctx;

	return ret;

err:
	geo_sampling_cleanup();
	return ret;
}

void geo_sampling_cleanup(void)
{
	if (_ctx_2 != NULL) {
		free_percpu(_ctx_2);
	}
	if (_ctx_4 != NULL) {
		free_percpu(_ctx_4);
	}
	if (_ctx_6 != NULL) {
		free_percpu(_ctx_6);
	}
	if (_ctx_8 != NULL) {
		free_percpu(_ctx_8);
	}
	if (_ctx_10 != NULL) {
		free_percpu(_ctx_10);
	}
}
