#include "vmlinux.h"
#include "bpf_helpers.h"
#include "common.h"
#include "fasthash.h"

char _license[] SEC("license") = "GPL";

#define __TARGET_ARCH_x86
#include <bpf/bpf_tracing.h>

/* set rate limit threshould here, less LIMIT_NUM, more Throughput, because the XDP_TX performance loss */
#define LIMIT_NUM 1
#define PERFORMANCE_TEST 1
#define DESIGN_PATTERN_TEST 0

#define FH_SEED (0x2d31e867)
#define L3_SEED (0x6ad611c3)

#define FORCE_INLINE inline __attribute__((__always_inline__))

/* from linux/socket.h */
#define AF_INET 2 /* Internet IP Protocol 	*/
#define AF_INET6 10 /* IP version 6			*/
/***********************/

/* from linux/filter.h */
#define BPF_NET_OFF (-0x100000)
#define BPF_LL_OFF (-0x200000)
/***********************/

/* Accept - allow any number of bytes */
/* Drop, cut packet to zero bytes */

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

unsigned long long load_byte(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.word");

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

/* lookup3.h start */
#define hashsize(n) ((__u32)1 << (n))
#define hashmask(n) (hashsize(n) - 1)
#define rot(x, k) (((x) << (k)) | ((x) >> (32 - (k))))

#define mix(a, b, c)             \
	{                        \
		a -= c;          \
		a ^= rot(c, 4);  \
		c += b;          \
		b -= a;          \
		b ^= rot(a, 6);  \
		a += c;          \
		c -= b;          \
		c ^= rot(b, 8);  \
		b += a;          \
		a -= c;          \
		a ^= rot(c, 16); \
		c += b;          \
		b -= a;          \
		b ^= rot(a, 19); \
		a += c;          \
		c -= b;          \
		c ^= rot(b, 4);  \
		b += a;          \
	}

#define final(a, b, c)           \
	{                        \
		c ^= b;          \
		c -= rot(b, 14); \
		a ^= c;          \
		a -= rot(c, 11); \
		b ^= a;          \
		b -= rot(a, 25); \
		c ^= b;          \
		c -= rot(b, 16); \
		a ^= c;          \
		a -= rot(c, 4);  \
		b ^= a;          \
		b -= rot(a, 14); \
		c ^= b;          \
		c -= rot(b, 24); \
	}

static __attribute__((always_inline)) __u32
hashlittle(const void *key, __u64 length, __u32 initval)
{
	__u32 a, b, c; /* internal state */
	const __u32 *k = (const __u32 *)key; /* read 32-bit chunks */
	const __u32 *end = k + (length / 12) * 3;
	const __u8 *k8;

	/* Set up the internal state */
	a = b = c = 0xdeadbeef + ((__u32)length) + initval;

	/*------ all but last block: aligned reads and affect 32 bits of (a,b,c) */
#pragma clang loop unroll(full)
	while (k != end) {
		a += k[0];
		b += k[1];
		c += k[2];
		mix(a, b, c);
		k += 3;
	}

	/*----------------------------- handle the last (probably partial) block */
	k8 = (const __u8 *)k;
	switch (length % 12) {
	case 12:
		c += k[2];
		b += k[1];
		a += k[0];
		break;
	case 11:
		c += ((__u32)k8[10]) << 16; /* fall through */
	case 10:
		c += ((__u32)k8[9]) << 8; /* fall through */
	case 9:
		c += k8[8]; /* fall through */
	case 8:
		b += k[1];
		a += k[0];
		break;
	case 7:
		b += ((__u32)k8[6]) << 16; /* fall through */
	case 6:
		b += ((__u32)k8[5]) << 8; /* fall through */
	case 5:
		b += k8[4]; /* fall through */
	case 4:
		a += k[0];
		break;
	case 3:
		a += ((__u32)k8[2]) << 16; /* fall through */
	case 2:
		a += ((__u32)k8[1]) << 8; /* fall through */
	case 1:
		a += k8[0];
		break;
	case 0:
		return c;
	}

	final(a, b, c);
	return c;
}
/* lookup3.h end */

/* fixed-point.h start */
#define FRACTION_BITS 32

typedef __u64 fpoint;

static __u64 FORCE_INLINE to_fixed_point(__u32 integer, __u32 fraction)
{
	return (((__u64)integer) << FRACTION_BITS) | (__u64)fraction;
}

static __u32 FORCE_INLINE to_int(fpoint a)
{
	return a >> FRACTION_BITS;
}

static fpoint FORCE_INLINE div_by_int(fpoint dividend, __u32 divisor)
{
	return dividend / divisor;
}
/* fixed-point.h end */

/* ewma.h start */
static __u32 FORCE_INLINE estimate_rate(__u32 old_rate, __u64 old_ts, __u64 now)
{
	// The window after which old observations are discarded.
	// Chosen to be a power of two so that division can be done
	// with a bit shift.
	const __u32 WINDOW_NS = 1ull << 27;
	const __u32 ONE_SECOND_NS = 1000000000ull;

	if (old_ts >= now) {
		// Time went backward or stood still due to clockskew. Return the old value,
		// since we can't compute the current rate.
		return old_rate;
	}

	__s64 elapsed = now - old_ts;
	if (old_ts == 0 || elapsed >= WINDOW_NS) {
		// Either there is no previous measurement, or it's too old.
		// We need another sample to calculate a reliable rate.
		return 0;
	}

	__u32 rate_current = ONE_SECOND_NS / (__u32)elapsed;
	if (old_rate == 0) {
		// This is the first time we can calculate a rate, so use that
		// to initialize our estimate.
		return rate_current;
	}

	const fpoint one = to_fixed_point(1, 0);
	fpoint a = div_by_int(to_fixed_point(elapsed, 0), WINDOW_NS);

	return to_int(a * rate_current + (one - a) * old_rate);
}
/* ewma.h end */

/* countmin.h start */
#define HASHFN_N 2
#define COLUMNS 512

_Static_assert((COLUMNS & (COLUMNS - 1)) == 0,
	       "COLUMNS must be a power of two");

struct cm_value {
	__u32 value;
	__u64 ts;
};

struct cm_hash {
	__u32 values[HASHFN_N];
};

struct countmin {
	struct cm_value values[HASHFN_N][COLUMNS];
};

// add element and determine count
static __u32 FORCE_INLINE cm_add_and_query(struct countmin *cm, __u64 now,
					   const struct cm_hash *h)
{
	__u32 min = -1;
#pragma clang loop unroll(full)
	for (int i = 0; i < ARRAY_SIZE(cm->values); i++) {
		__u32 target_idx = h->values[i] &
				   (ARRAY_SIZE(cm->values[i]) - 1);
		struct cm_value *value = &cm->values[i][target_idx];
		value->value = estimate_rate(value->value, value->ts, now);
		value->ts = now;
		if (value->value < min) {
			min = value->value;
		}
	}
	return min;
}
/* countmin.h end */

enum address_gen {
	ADDRESS_IP = 0, // /32 or /128
	ADDRESS_NET = 1, // /24 or /48
	ADDRESS_WILDCARD = 2, // /0
};

enum port_gen {
	PORT_SPECIFIED = 0,
	PORT_WILDCARD = 1,
};

struct gen {
	int level;
	enum address_gen source;
	enum port_gen source_port;
	enum address_gen dest;
	enum port_gen dest_port;
	bool evaluate;
};

struct address_hash {
	__u64 vals[ADDRESS_WILDCARD];
};

struct hash_t {
	struct address_hash src;
	struct address_hash dst;
	__u64 src_port;
	__u64 dst_port;
};

static const struct gen generalisations[] = {
	/*level 0*/
	{ 0, ADDRESS_IP, PORT_SPECIFIED, ADDRESS_IP, PORT_SPECIFIED, true },

	/* level 1 */
	{ 1, ADDRESS_NET, PORT_SPECIFIED, ADDRESS_IP, PORT_SPECIFIED, false },
	{ 1, ADDRESS_IP, PORT_WILDCARD, ADDRESS_IP, PORT_SPECIFIED, false },
	{ 1, ADDRESS_IP, PORT_SPECIFIED, ADDRESS_IP, PORT_WILDCARD, true },

	/* level 2 */
	/* *.*.*.*:i --> w.x.y.z:j */
	{ 2, ADDRESS_WILDCARD, PORT_SPECIFIED, ADDRESS_IP, PORT_SPECIFIED,
	  false },
	/* a.b.c.*:* --> w.x.y.z:j */
	{ 2, ADDRESS_NET, PORT_WILDCARD, ADDRESS_IP, PORT_SPECIFIED, false },
	/* a.b.c.*:i --> w.x.y.z:* */
	{ 2, ADDRESS_NET, PORT_SPECIFIED, ADDRESS_IP, PORT_WILDCARD, false },
	/* a.b.c.d:* --> w.x.y.z:* */
	{ 2, ADDRESS_IP, PORT_WILDCARD, ADDRESS_IP, PORT_WILDCARD, true },

	/* level 3 */
	/* *.*.*.*:* --> w.x.y.z:j */
	{ 3, ADDRESS_WILDCARD, PORT_WILDCARD, ADDRESS_IP, PORT_SPECIFIED,
	  false },
	/* *.*.*.*:i --> w.x.y.z:* */
	{ 3, ADDRESS_WILDCARD, PORT_SPECIFIED, ADDRESS_IP, PORT_WILDCARD,
	  false },
	/* A.B.C.*:* --> w.x.y.z:* */
	{ 3, ADDRESS_NET, PORT_WILDCARD, ADDRESS_IP, PORT_WILDCARD, true },

	/* level 4 */
	{ 4, ADDRESS_WILDCARD, PORT_WILDCARD, ADDRESS_IP, PORT_WILDCARD, true },
};

// collect number of packet drops per level
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 5);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct countmin);
	__uint(max_entries, ARRAY_SIZE(generalisations));
} countmin SEC(".maps");

static FORCE_INLINE void ipv6_hash(const struct in6_addr *ip,
				   struct address_hash *a,
				   struct address_hash *b)
{
	a->vals[ADDRESS_IP] = fasthash64(ip, sizeof(*ip), FH_SEED);
	b->vals[ADDRESS_IP] = hashlittle(ip, sizeof(*ip), L3_SEED);
	a->vals[ADDRESS_NET] = fasthash64(ip, 48 / 8, FH_SEED);
	b->vals[ADDRESS_NET] = hashlittle(ip, 48 / 8, L3_SEED);
}

static FORCE_INLINE void ipv4_hash(struct in_addr ip, struct address_hash *a,
				   struct address_hash *b)
{
	a->vals[ADDRESS_IP] = fasthash64(&ip, sizeof(ip), FH_SEED);
	b->vals[ADDRESS_IP] = hashlittle(&ip, sizeof(ip), L3_SEED);
	ip.s_addr &= 0xffffff00;
	a->vals[ADDRESS_NET] = fasthash64(&ip, sizeof(ip), FH_SEED);
	b->vals[ADDRESS_NET] = hashlittle(&ip, sizeof(ip), L3_SEED);
}

static FORCE_INLINE __u64 hash_mix(__u64 a, __u64 b)
{
	// Adapted from https://stackoverflow.com/a/27952689. The constant below
	// is derived from the golden ratio.
	a ^= b + 0x9e3779b97f4a7c15 + (a << 6) + (a >> 2);
	return a;
}

static FORCE_INLINE __u32 gen_hash(const struct gen *gen,
				   const struct hash_t *ph)
{
	__u64 tmp = 0;

	if (gen->source != ADDRESS_WILDCARD) {
		tmp = hash_mix(tmp, ph->src.vals[gen->source]);
	}

	if (gen->dest != ADDRESS_WILDCARD) {
		tmp = hash_mix(tmp, ph->dst.vals[gen->dest]);
	}

	if (gen->source_port != PORT_WILDCARD) {
		tmp = hash_mix(tmp, ph->src_port);
	}

	if (gen->dest_port != PORT_WILDCARD) {
		tmp = hash_mix(tmp, ph->dst_port);
	}

	// Adapted from fasthash32
	return tmp - (tmp >> 32);
}

static __u32 FORCE_INLINE add_to_node(__u32 node_idx, __u64 ts,
				      const struct cm_hash *h)
{
	struct countmin *node = bpf_map_lookup_elem(&countmin, &node_idx);
	if (node == NULL) {
		return -1;
	}
	return cm_add_and_query(node, ts, h);
}

static FORCE_INLINE void log_level_drop(__u32 level)
{
	__u64 *count = bpf_map_lookup_elem(&stats, &level);
	if (count == NULL) {
		return;
	}
	(*count)++;
}

static FORCE_INLINE int drop_or_accept(__u32 level, fpoint limit,
				       __u32 max_rate, __u32 rand)
{
	if (div_by_int(to_fixed_point(limit, 0), max_rate) <
	    to_fixed_point(0, rand)) {
		log_level_drop(level);
		return XDP_DROP;
	}
	return XDP_TX;
}

static __attribute__((always_inline)) int
process_packet(struct pkt_5tuple *pkt, __u64 ts, __u32 rand,
	       __u64 *rate_exceeded_level)
{
	__u32 limit = LIMIT_NUM;

	struct hash_t ph[HASHFN_N];
	struct in6_addr ipv6;
	struct in_addr ipv4;
	__u32 max_rate = 0;

	__u64 troff;
	ipv4.s_addr = pkt->src_ip;
	ipv4_hash(ipv4, &ph[0].src, &ph[1].src);
	ipv4.s_addr = pkt->dst_ip;
	ipv4_hash(ipv4, &ph[0].dst, &ph[1].dst);

	__u16 src_port = pkt->src_port;
	ph[0].src_port = fasthash64(&src_port, sizeof(src_port), FH_SEED);
	ph[1].src_port = hashlittle(&src_port, sizeof(src_port), L3_SEED);
	__u16 dst_port = pkt->dst_port;
	ph[0].dst_port = fasthash64(&dst_port, sizeof(dst_port), FH_SEED);
	ph[1].dst_port = hashlittle(&dst_port, sizeof(dst_port), L3_SEED);

#pragma clang loop unroll(full)
	for (int i = 0; i < ARRAY_SIZE(generalisations); i++) {
		const struct gen *gen = &generalisations[i];
		const int level = gen->level;

		// Force clang to inline level on the stack rather than loading it from
		// .rodata later on.
		asm volatile("" : : "r"(level) : "memory");

		struct cm_hash h = { {
			gen_hash(gen, &ph[0]),
			gen_hash(gen, &ph[1]),
		} };
#if DESIGN_PATTERN_TEST == 0
		__u32 rate = add_to_node(i, ts, &h);
#else
		__u32 rate = 65535;
#endif
		if (rate > max_rate) {
			max_rate = rate;
		}

		if (gen->evaluate) {
			if (max_rate > limit) {
				if (rate_exceeded_level != NULL) {
					*rate_exceeded_level = level;
				}
				return drop_or_accept(level, limit, max_rate,
						      rand);
			}

			max_rate = 0;
		}
	}

	return XDP_TX;
}

/* exp program */
SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	int zero = 0;

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
			pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port,
			pkt.proto);
	}

	int res = process_packet(&pkt, bpf_ktime_get_ns(),
				 bpf_get_prandom_u32(), NULL);

/* For performance test, directly return XDP_DROP */
#if PERFORMANCE_TEST == 0
	if (res == XDP_TX) {
		return XDP_TX;
	} else {
		return XDP_DROP;
	}
#endif

finish:
	return XDP_DROP;
}