#include "common.h"
#include "vmlinux.h"
#include "bpf_hash_alg_simd.h"

#define PACKET_ATTRS                                                    \
	.src_ip = 0x01020304, .dst_ip = 0x05060708, .src_port = 0x090a, \
	.dst_port = 0x0b0c, .proto = 0x06
#define SEEDx1 0x01020304
#define SEEDx4 SEEDx1, 0x05060708, 0x090a0b0c, 0x0d0e0f10
#define SEEDx8 SEEDx4, 0x11121314, 0x15161718, 0x191a1b1c, 0x1d1e1f20

char _license[] SEC("license") = "GPL";

static inline void __memcpy_n(u8 *dest, const u8 *src, size_t n)
{
	for (int i = 0; i < n; i++) {
		dest[i] = src[i];
	}
}

static inline void test_bpf_xxh32_avx2_pkt5(void)
{
	struct pkt_5tuple pkt = { PACKET_ATTRS };
	u32 seeds[8] = { SEEDx8 };
	u32 dest[8] = { 0 };

	log_info("xxh32_avx2_pkt5() test started\n");

	bpf_xxh32_avx2_pkt5(&pkt, seeds, dest);

	for (int i = 0; i < 8; i++) {
		log_debug("dest[%d] = 0x%x\n", i, dest[i]);
	}

	log_info("xxh32_avx2_pkt5() test passed\n");
}

static inline void test_bpf_xxh32_avx2_pkt5_pkts(void)
{
	struct pkt_5tuple pkt = { PACKET_ATTRS };
	u32 seed = SEEDx1;
	u32 dest[8] = { 0 };

	log_info("xxh32_avx2_pkt5_pkts() test started\n");

	u32 data[32] = { 0 };
	int i, j;
	size_t copy_size;
	for (i = 0; i < 4; i++) {
		copy_size = i != 3 ? sizeof(u32) : 1;
		for (j = 0; j < 8; j++) {
			__memcpy_n((u8 *)(data + i * 8 + j), (u8 *)&seed,
				   copy_size);
		}
	}

	bpf_xxh32_avx2_pkt5_pkts(data, seed, dest);

	for (int i = 0; i < 8; i++) {
		/* 8 hashes should be the same */
		log_debug("dest[%d] = 0x%x\n", i, dest[i]);
	}

	log_info("xxh32_avx2_pkt5_pkts() test passed\n");
}

static inline void test_bpf_fasthash32_avx2(void)
{
	struct pkt_5tuple pkt = { PACKET_ATTRS };
	u32 seeds[4] = { SEEDx4 };
	u32 dest[4] = { 0 };

	log_info("bpf_fasthash32_avx2() test started\n");

	bpf_fasthash32_avx2(&pkt, sizeof(pkt), seeds, dest);

	for (int i = 0; i < 4; i++) {
		log_debug("dest[%d] = 0x%x\n", i, dest[i]);
	}

	log_info("bpf_fasthash32_avx2() test passed\n");
}

static inline void test_bpf_fasthash32_alt_avx2(void)
{
	struct pkt_5tuple pkt = { PACKET_ATTRS };
	u32 seeds[8] = { SEEDx8 };
	u32 dest[8] = { 0 };

	log_info("bpf_fasthash32_alt_avx2() test started\n");

	bpf_fasthash32_alt_avx2(&pkt, sizeof(pkt), seeds, dest);

	for (int i = 0; i < 8; i++) {
		log_debug("dest[%d] = 0x%x\n", i, dest[i]);
	}

	log_info("bpf_fasthash32_alt_avx2() test passed\n");
}

static inline void test_bpf_fasthash32_alt_avx2_pkt5(void)
{
	struct pkt_5tuple pkt = { PACKET_ATTRS };
	u32 seeds[8] = { SEEDx8 };
	u32 dest[8] = { 0 };

	log_info("bpf_fasthash32_alt_avx2_pkt5() test started\n");

	bpf_fasthash32_alt_avx2_pkt5(&pkt, seeds, dest);

	for (int i = 0; i < 8; i++) {
		log_debug("dest[%d] = 0x%x\n", i, dest[i]);
	}

	log_info("bpf_fasthash32_alt_avx2_pkt5() test passed\n");
}

SEC("xdp") int xdp_main(struct xdp_md *ctx)
{
	// test_bpf_xxh32_avx2_pkt5();
	// test_bpf_xxh32_avx2_pkt5_pkts();
	test_bpf_fasthash32_avx2();
	test_bpf_fasthash32_alt_avx2();
	test_bpf_fasthash32_alt_avx2_pkt5();

	return XDP_PASS;
}
