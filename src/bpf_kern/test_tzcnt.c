#include "common.h"
#include "bpf_cmp_alg_simd.h"
#include "vmlinux.h"

static u32 index __attribute__((used));

char _license[] SEC("license") = "GPL";

static inline u32 __tzcnt_u32(u32 v)
{
	v = v - (v & (v - 1));
	return (((v & 0xFFFF0000) != 0 ? (v &= 0xFFFF0000, 16) : 0) |
		((v & 0xFF00FF00) != 0 ? (v &= 0xFF00FF00, 8) : 0) |
		((v & 0xF0F0F0F0) != 0 ? (v &= 0xF0F0F0F0, 4) : 0) |
		((v & 0xCCCCCCCC) != 0 ? (v &= 0xCCCCCCCC, 2) : 0) |
		((v & 0xAAAAAAAA) != 0));
}

SEC("xdp") int xdp_main(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data,
	     *data_end = (void *)(long)ctx->data_end;
	u32 val;

	if (data + sizeof(val) > data_end) {
		log_error(
			"test_bpf_cmp_alg_simd: data + sizeof(val) > data_end");
		goto out;
	} else {
		val = *(u32 *)data;
	}

#if USE_IMPL == EBPF_IMPL
	log_debug("test_tzcnt: using eBPF implementation");
	index = __tzcnt_u32(val);
#else
	log_debug("test_tzcnt: using HyperCom implementation");
	index = bpf_tzcnt_u32(val);
#endif

	log_debug("test_bpf_cmp_alg_simd: val = %u, index = %u", val, index);

out:
	return XDP_DROP;
}
