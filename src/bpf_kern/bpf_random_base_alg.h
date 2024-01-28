#ifndef _BPF_RANDOM_BASE_ALG_H
#define _BPF_RANDOM_BASE_ALG_H

#include <bpf/bpf_helpers.h>

#define MAX_GEOSAMPLING_SIZE 1024
#define ____cacheline_aligned __attribute__((aligned(64)))

typedef u32 geo_cnt_t;

struct geo_sampling_ctx {
	geo_cnt_t cnt;
	u32 geo_sampling_idx ____cacheline_aligned;
	geo_cnt_t pool[MAX_GEOSAMPLING_SIZE] ____cacheline_aligned;
};

extern struct geo_sampling_ctx *bpf_geo_sampling_ctx_new(void) __ksym;

extern void bpf_geo_sampling_ctx_free(struct geo_sampling_ctx *ctx) __ksym;

extern bool bpf_geo_sampling_should_do(struct geo_sampling_ctx *ctx) __ksym;

extern geo_cnt_t
bpf_geo_sampling_gen_geo_cnt(struct geo_sampling_ctx *ctx) __ksym;

#endif
