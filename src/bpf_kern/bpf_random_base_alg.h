#ifndef _BPF_RANDOM_BASE_ALG_H
#define _BPF_RANDOM_BASE_ALG_H

#include <bpf/bpf_helpers.h>

#define MAX_GEOSAMPLING_SIZE 1024
#define ____cacheline_aligned __attribute__((aligned(64)))

struct geo_sampling_ctx {
	u32 cnt;
	u32 geo_sampling_idx ____cacheline_aligned;
	u32 pool[MAX_GEOSAMPLING_SIZE] ____cacheline_aligned;
};

extern struct geo_sampling_ctx *bpf_geo_sampling_ctx_new(void) __ksym;
extern void bpf_geo_sampling_ctx_free(struct geo_sampling_ctx *ctx) __ksym;
extern bool bpf_geo_sampling_should_do(struct geo_sampling_ctx *ctx) __ksym;

#endif
