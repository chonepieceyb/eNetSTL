#include "bpf_cmp_alg_simd.h"
#include "common.h"
#include "fasthash.h"
#include "vmlinux.h"

static u32 index __attribute__((used));

char _license[] SEC("license") = "GPL";
#define HASHSEED 0xdeadbeef

#define USE_EBPF_IMPL

SEC("xdp") int xdp_main(struct xdp_md *ctx)
{
	__u32 zero = 0;
	struct pkt_5tuple pkt;
	void *data, *data_end;
	struct hdr_cursor nh;
	int ret;

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	nh.pos = data;
	if (unlikely((ret = parse_pkt_5tuple(&nh, data_end, &pkt)) != 0)) {
		log_error("cannot parse packet: %d", ret);
		goto finish;
	} else {
		log_debug(
			"pkt: src_ip=0x%08x src_port=0x%04x dst_ip=0x%08x dst_port=0x%04x proto=0x%02x",
			pkt.src_ip, pkt.src_port, pkt.dst_ip,
			pkt.dst_port, pkt.proto);
	}

#ifdef USE_EBPF_IMPL
	__u32 hash_value = fasthash32(&pkt, sizeof(struct pkt_5tuple), HASHSEED);
#else
	__u32 hash_value = bpf_crc32_hash(&pkt, sizeof(struct pkt_5tuple), HASHSEED);
#endif

	if (hash_value == 0) {
		log_debug("unexpected hash value");
		return XDP_TX;
	}
	if(pkt.dst_port == 9999) {
		return XDP_TX;
	}

finish:
	return XDP_DROP;
}
