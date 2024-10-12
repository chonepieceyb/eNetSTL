#include "../vmlinux.h"
#include "../common.h"
#include "./sk_config.h"

char _license[] SEC("license") = "GPL";

PACKET_COUNT_MAP_DEFINE

#define HASHFN_N 6

#define M 0x880355f21e6d1965ULL

_Static_assert((COLUMNS & (COLUMNS - 1)) == 0,
	       "COLUMNS must be a power of two");

extern void bpf_hash_smid_cnt_u32(const struct pkt_5tuple *buf, void *mem,
				  u64 size__sz, u32 column_shift) __ksym;

static __u32 seeds[] = {
	0xec5853,  0xec5859,  0xec5861,	 0xec587f,  0xec58a7,  0xec58b3,
	0xec58c7,  0xec58d1,  0xec58531, 0xec58592, 0xec58613, 0xec587f4,
	0xec58a75, 0xec58b36, 0xec58c77, 0xec58d18, 0xec58539, 0xec58510,
	0xec58611, 0xec58712, 0xec58a13, 0xec58b14, 0xec58c15, 0xec58d16,
	0xec58521, 0xec58522, 0xec58623, 0xec58724, 0xec58a25, 0xec58b26,
	0xec58c27, 0xec58d28, 0xec58541, 0xec58542, 0xec58643, 0xec58744,
	0xec58a45, 0xec58b46, 0xec58c47, 0xec58d48, 0xec58551, 0xec58552,
	0xec58653, 0xec58754, 0xec58a55, 0xec58b56, 0xec58c57, 0xec58d58,
	0xec58561, 0xec58563, 0xec58663, 0xec58764, 0xec58a65, 0xec58b66,
	0xec58c67, 0xec58d68, 0xec58571, 0xec58572, 0xec58673, 0xec58774,
	0xec58a75, 0xec58b76, 0xec58c77, 0xec58d78,
};

struct countmin {
	__u32 values[HASHFN_N][COLUMNS];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct countmin);
	__uint(max_entries, 1);
} countmin SEC(".maps");

static void __always_inline countmin_add_eNetSTL(struct countmin *cm,
						 void *element, __u64 len)
{
	bpf_hash_smid_cnt_u32((struct pkt_5tuple *)element, (void *)cm,
			      sizeof(*cm), 8); //COLUNM_SHIT 8
}

SEC("xdp") int xdp_main(struct xdp_md *ctx)
{
	LATENCY_START_TIMESTAMP_DEFINE

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };
	struct pkt_5tuple pkt;
	uint32_t zero = 0;
	struct countmin *cm;
	int ret = 0;
	if ((ret = parse_pkt_5tuple(&nh, data_end, &pkt)) != 0) {
		log_error(" failed to parse packet: %d", ret);
		goto out;
	}

	cm = bpf_map_lookup_elem(&countmin, &zero);
	if (!cm) {
		log_error(" invalid entry in the countmin sketch");
		goto out;
	}
	countmin_add_eNetSTL(cm, &pkt, sizeof(pkt));

	PACKET_COUNT_MAP_UPDATE

#ifdef LATENCY_EXP
	SWAP_MAC_AND_RETURN_XDP_TX(ctx) 
#endif
out:
	return XDP_DROP;
}