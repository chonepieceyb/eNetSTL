#include "../vmlinux.h"
#include "../common.h"

#define efd_log(level, fmt, ...)                                          \
	log_##level("efd (scmap): " fmt " (%s @ line %d)", ##__VA_ARGS__, \
		    __func__, __LINE__)

/* Following options MUST be consistent with the LKM side */

#define EFD_VALUE_NUM_BITS 8
#define EFD_MAX_NUM_RULES 2816

#if (EFD_VALUE_NUM_BITS > 0 && EFD_VALUE_NUM_BITS <= 8)
typedef uint8_t efd_value_t;
#elif (EFD_VALUE_NUM_BITS > 8 && EFD_VALUE_NUM_BITS <= 16)
typedef uint16_t efd_value_t;
#elif (EFD_VALUE_NUM_BITS > 16 && EFD_VALUE_NUM_BITS <= 32)
typedef uint32_t efd_value_t;
#else
#error("EFD_VALUE_NUM_BITS must be in the range [1:32]")
#endif

#define inline inline __attribute__((always_inline))

struct pkt_5tuple_with_pad {
	struct pkt_5tuple pkt;
	uint8_t __pad[3];
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_STATIC_CUSTOM_MAP);
	__uint(max_entries, EFD_MAX_NUM_RULES);
	__type(key, struct pkt_5tuple_with_pad);
	__type(value, efd_value_t);
} efd_table_map SEC(".maps");

static efd_value_t dummy __attribute__((used)) = 0;

char _license[] SEC("license") = "GPL";

SEC("xdp") int xdp_main(struct xdp_md *ctx)
{
	struct pkt_5tuple_with_pad pkt = { 0 };
	struct hdr_cursor nh = { .pos = (void *)(long)ctx->data };
	void *data_end = (void *)(long)ctx->data_end;
	int ret, zero = 0;
	efd_value_t *value;

	if (unlikely((ret = parse_pkt_5tuple(&nh, data_end, &pkt.pkt)) != 0)) {
		efd_log(error, "parse_pkt_5tuple failed: %d", ret);
		goto out;
	} else {
		efd_log(debug,
			"pkt: src_ip = 0x%08x, dst_ip = 0x%08x, src_port = 0x%04x, dst_port = 0x%04x, proto = 0x%02x",
			pkt.pkt.src_ip, pkt.pkt.dst_ip, pkt.pkt.src_port,
			pkt.pkt.dst_port, pkt.pkt.proto);
	}

	value = bpf_map_lookup_elem(&efd_table_map, &pkt);
	if (unlikely(!value)) {
		efd_log(error, "bpf_map_lookup_elem failed");
		goto out;
	}
	dummy = *value;
	efd_log(debug, "test result = %d", dummy);

out:
	return XDP_DROP;
}
