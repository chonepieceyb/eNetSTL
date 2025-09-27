#ifndef EBPF_DEMO_COMMON_H
#define EBPF_DEMO_COMMON_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/errno.h>

#ifndef LOG_LEVEL
#define LOG_LEVEL 2
#endif

#define LOG_LEVEL_DEBUG 3
#define LOG_LEVEL_INFO 2
#define LOG_LEVEL_WARN 1
#define LOG_LEVEL_ERROR 0

// #define COLOR_RED "\033[0;31m"
// #define COLOR_GREEN "\033[0;32m"
// #define COLOR_YELLOW "\033[1;33m"
// #define COLOR_ORIGIN "\033[0;33m"
// #define COLOR_OFF "\033[0m"

/*
*DEBUG: LEVEL=4
*INFO: LEVEL=3
*WARN: LEVEL=2
*ERROR: LEVEL=1
*/

#if LOG_LEVEL >= LOG_LEVEL_DEBUG
#define log_debug(FMT, ...) ({ bpf_printk("[DEBUG]" FMT, ##__VA_ARGS__); })
#else
#define log_debug(fmt, ...) ({})
#endif

#if LOG_LEVEL >= LOG_LEVEL_INFO
#define log_info(FMT, ...) ({ bpf_printk("[INFO]" FMT, ##__VA_ARGS__); })
#else
#define log_info(fmt, ...) ({})
#endif

#if LOG_LEVEL >= LOG_LEVEL_WARN
#define log_warn(FMT, ...) ({ bpf_printk("[WARN]" FMT, ##__VA_ARGS__); })
#else
#define log_warn(fmt, ...) ({})
#endif

#if LOG_LEVEL >= LOG_LEVEL_ERROR
#define log_error(FMT, ...) ({ bpf_printk("[ERROR]" FMT, ##__VA_ARGS__); })
#else
#define log_error(fmt, ...) ({})
#endif

#define ANY_IMPL 0
#define EBPF_IMPL 1
#define EBPF_WITH_HYPERCOM_INTRINSIC_IMPL 2
#define HYPERCOM_IMPL 3

#ifndef likely
#define likely(X) __builtin_expect(!!(X), 1)
#endif

#ifndef unlikely
#define unlikely(X) __builtin_expect(!!(X), 0)
#endif

#ifndef build_bug_on
#define build_bug_on(E) ((void)sizeof(char[1 - 2 * !!(E)]))
#endif

#ifndef lock_xadd
#define lock_xadd(P, V) ((void)__sync_fetch_and_add((P), (V)))
#endif

#define LOG2(x)                       \
	({                            \
		unsigned _x = (x);    \
		unsigned _result = 0; \
		while (_x >>= 1) {    \
			_result++;    \
		}                     \
		_result;              \
	})

#define SHIFT_TO_SIZE(_shift) ((unsigned long)1 << (_shift))

#define BOUND_INDEX(idx, shift)                             \
	({                                                  \
		typeof(idx) __idx;                          \
		__idx = (idx) & (SHIFT_TO_SIZE(shift) - 1); \
	})

/* linux __ffs software implementation*/
static __always_inline __u64 __ffs64(__u64 word)
{
	int num = 0;

	if ((word & 0xffffffff) == 0) {
		num += 32;
		word >>= 32;
	}
	if ((word & 0xffff) == 0) {
		num += 16;
		word >>= 16;
	}
	if ((word & 0xff) == 0) {
		num += 8;
		word >>= 8;
	}
	if ((word & 0xf) == 0) {
		num += 4;
		word >>= 4;
	}
	if ((word & 0x3) == 0) {
		num += 2;
		word >>= 2;
	}
	if ((word & 0x1) == 0)
		num += 1;
	return num;
}

static __always_inline __u32 __ffs32(__u32 word)
{
	int num = 0;
	if ((word & 0xffff) == 0) {
		num += 16;
		word >>= 16;
	}
	if ((word & 0xff) == 0) {
		num += 8;
		word >>= 8;
	}
	if ((word & 0xf) == 0) {
		num += 4;
		word >>= 4;
	}
	if ((word & 0x3) == 0) {
		num += 2;
		word >>= 2;
	}
	if ((word & 0x1) == 0)
		num += 1;
	return num;
}

#define STR(s) #s
#define XSTR(s) STR(s)

#define asm_bound_check(variable, max_size)                        \
	({                                                         \
		asm volatile("%[tmp] &= " XSTR(max_size - 1) " \n" \
			     : [tmp] "+&r"(variable));             \
	})

#define xdp_assert(expr, name)                                                 \
	({                                                                     \
		if (unlikely(!(expr))) {                                       \
			log_error("[xdp assert failed]: unexpected %s", name); \
			goto xdp_error;                                        \
		};                                                             \
	})

#define xdp_assert_eq(expected, actual, name)                                                         \
	({                                                                                            \
		typeof(actual) ___act = (actual);                                                     \
		typeof(expected) ___exp = (expected);                                                 \
		bool ___ok = ___act == ___exp;                                                        \
		if (unlikely(!___ok)) {                                                               \
			log_error(                                                                    \
				"[xdp assert failed]: unexpected %s: actual %lld != expected %lld\n", \
				name, (long long)___act, (long long)___exp);                          \
			goto xdp_error;                                                               \
		};                                                                                    \
	})

#define xdp_assert_neq(noexpected, actual, name)                                                          \
	({                                                                                                \
		typeof(actual) ___act = (actual);                                                         \
		typeof(noexpected) ___noexp = (noexpected);                                               \
		bool ___ok = ___act != ___noexp;                                                          \
		if (unlikely(!___ok)) {                                                                   \
			log_error(                                                                        \
				"[xdp assert failed]: unexpected %s: actual %lld == non expected %lld\n", \
				name, (long long)___act, (long long)___noexp);                            \
			goto xdp_error;                                                                   \
		};                                                                                        \
	})

#define min(x, y)                              \
	({                                     \
		typeof(x) _min1 = (x);         \
		typeof(y) _min2 = (y);         \
		(void)(&_min1 == &_min2);      \
		_min1 < _min2 ? _min1 : _min2; \
	})
#define xdp_assert_tag(expr, name, tag)                                        \
	({                                                                     \
		if (unlikely(!(expr))) {                                       \
			log_error("[xdp assert failed]: unexpected %s", name); \
			goto tag;                                              \
		};                                                             \
	})

#define xdp_assert_eq_tag(expected, actual, name, tag)                                                \
	({                                                                                            \
		typeof(actual) ___act = (actual);                                                     \
		typeof(expected) ___exp = (expected);                                                 \
		bool ___ok = ___act == ___exp;                                                        \
		if (unlikely(!___ok)) {                                                               \
			log_error(                                                                    \
				"[xdp assert failed]: unexpected %s: actual %lld != expected %lld\n", \
				name, (long long)___act, (long long)___exp);                          \
			goto tag;                                                                     \
		};                                                                                    \
	})

#define xdp_assert_neq_tag(noexpected, actual, name, tag)                                                 \
	({                                                                                                \
		typeof(actual) ___act = (actual);                                                         \
		typeof(noexpected) ___noexp = (noexpected);                                               \
		bool ___ok = ___act != ___noexp;                                                          \
		if (unlikely(!___ok)) {                                                                   \
			log_error(                                                                        \
				"[xdp assert failed]: unexpected %s: actual %lld == non expected %lld\n", \
				name, (long long)___act, (long long)___noexp);                            \
			goto tag;                                                                         \
		};                                                                                        \
	})

#define max(x, y)                              \
	({                                     \
		typeof(x) _max1 = (x);         \
		typeof(y) _max2 = (y);         \
		(void)(&_max1 == &_max2);      \
		_max1 > _max2 ? _max1 : _max2; \
	})

#define typecheck(type, x)                     \
	({                                     \
		type __dummy;                  \
		typeof(x) __dummy2;            \
		(void)(&__dummy == &__dummy2); \
		1;                             \
	})

#define CHECK_BOUND(p, data_end)                      \
	do {                                          \
		if ((void *)((p) + 1) > (data_end)) { \
			goto out_of_bound;            \
		}                                     \
	} while (0)

#define ETH_P_IP 0x0800

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

struct pkt_5tuple {
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	uint8_t proto;
} __attribute__((packed));

struct __ports {
	__be16 src_port;
	__be16 dst_port;
} __attribute__((packed));

struct hdr_cursor {
	void *pos;
};

struct pkt_count {
	__u64 rx_count;
	__u64 lat_count;
};

/**
 * parse_pkt_5tuple() - Parse into packet 5-tuple.
 * 
 * @nh: Cursor
 * @data_end: `(void *)(long)ctx->data_end`
 * @pkt: Packet 5-tuple to parse into (source/destination IPs/ports are not
 *       converted to host byte order)
 * 
 * Return: 0 if successful, `-EINVAL` if failed to parse.
 */
static __always_inline int32_t parse_pkt_5tuple(struct hdr_cursor *nh,
						void *data_end,
						struct pkt_5tuple *pkt)
{
	struct ethhdr *eth;
	struct iphdr *ip;
	struct __ports *ports;

	log_debug("parse_pkt_5tuple: start parsing, data_pos=%p, data_end=%p", nh->pos, data_end);

	eth = nh->pos;
	CHECK_BOUND(eth, data_end);
	log_debug("parse_pkt_5tuple: eth header bound check passed, proto=%d", eth->h_proto);
	if (unlikely(eth->h_proto != bpf_htons(ETH_P_IP))) {
		log_debug(
			" cannot parse pkt_5tuple: unsupported protocol in Ethernet header: %d (!= %d)",
			eth->h_proto, bpf_htons(ETH_P_IP));
		goto unsupported;
	}
	nh->pos += sizeof(*eth);
	log_debug("parse_pkt_5tuple: moved past eth header, new pos=%p", nh->pos);

	ip = nh->pos;
	CHECK_BOUND(ip, data_end);
	log_debug("parse_pkt_5tuple: ip header bound check passed, protocol=%d", ip->protocol);
	if (unlikely(ip->protocol != IPPROTO_TCP &&
		     ip->protocol != IPPROTO_UDP)) {
		log_debug(
			" cannot parse pkt_5tuple: unsupported protocol in IP header %d (not in %d, %d)",
			ip->protocol, IPPROTO_TCP, IPPROTO_UDP);
		goto unsupported;
	}
	nh->pos += sizeof(*ip);
	log_debug("parse_pkt_5tuple: moved past ip header, new pos=%p", nh->pos);

	ports = nh->pos;
	CHECK_BOUND(ports, data_end);
	log_debug("parse_pkt_5tuple: ports bound check passed, src_port=%d, dst_port=%d", ports->src_port, ports->dst_port);

	pkt->src_ip = bpf_ntohl(ip->saddr);
	pkt->dst_ip = bpf_ntohl(ip->daddr);
	pkt->proto = ip->protocol;
	pkt->src_port = bpf_ntohs(ports->src_port);
	pkt->dst_port = bpf_ntohs(ports->dst_port);

	log_debug("parse_pkt_5tuple: successfully parsed, src_ip=%x, dst_ip=%x, proto=%d, src_port=%d, dst_port=%d",
		pkt->src_ip, pkt->dst_ip, pkt->proto, pkt->src_port, pkt->dst_port);
	return 0;

out_of_bound:
	log_debug("parse_pkt_5tuple: out_of_bound error at pos=%p", nh->pos);
	return -EINVAL;
unsupported:
	return -EINVAL;
}

#define NO_TEAR_ADD(x, val) WRITE_ONCE((x), READ_ONCE(x) + (val))
#define NO_TEAR_INC(x) NO_TEAR_ADD((x), 1)

typedef __u8 __attribute__((__may_alias__)) __u8_alias_t;
typedef __u16 __attribute__((__may_alias__)) __u16_alias_t;
typedef __u32 __attribute__((__may_alias__)) __u32_alias_t;
typedef __u64 __attribute__((__may_alias__)) __u64_alias_t;

static __always_inline void __read_once_size_custom(const volatile void *p,
						    void *res, int size)
{
	switch (size) {
	case 1:
		*(__u8_alias_t *)res = *(volatile __u8_alias_t *)p;
		break;
	case 2:
		*(__u16_alias_t *)res = *(volatile __u16_alias_t *)p;
		break;
	case 4:
		*(__u32_alias_t *)res = *(volatile __u32_alias_t *)p;
		break;
	case 8:
		*(__u64_alias_t *)res = *(volatile __u64_alias_t *)p;
		break;
	default:
		asm volatile("" : : : "memory");
		__builtin_memcpy((void *)res, (const void *)p, size);
		asm volatile("" : : : "memory");
	}
}

static __always_inline void __write_once_size_custom(volatile void *p,
						     void *res, int size)
{
	switch (size) {
	case 1:
		*(volatile __u8_alias_t *)p = *(__u8_alias_t *)res;
		break;
	case 2:
		*(volatile __u16_alias_t *)p = *(__u16_alias_t *)res;
		break;
	case 4:
		*(volatile __u32_alias_t *)p = *(__u32_alias_t *)res;
		break;
	case 8:
		*(volatile __u64_alias_t *)p = *(__u64_alias_t *)res;
		break;
	default:
		asm volatile("" : : : "memory");
		__builtin_memcpy((void *)p, (const void *)res, size);
		asm volatile("" : : : "memory");
	}
}

#define READ_ONCE(x)                                               \
	({                                                         \
		union {                                            \
			typeof(x) __val;                           \
			char __c[1];                               \
		} __u = { .__c = { 0 } };                          \
		__read_once_size_custom(&(x), __u.__c, sizeof(x)); \
		__u.__val;                                         \
	})

#define WRITE_ONCE(x, val)                                          \
	({                                                          \
		union {                                             \
			typeof(x) __val;                            \
			char __c[1];                                \
		} __u = { .__val = (val) };                         \
		__write_once_size_custom(&(x), __u.__c, sizeof(x)); \
		__u.__val;                                          \
	})

#endif

#define PACKET_COUNT_MAP_DEFINE                   \
	struct {                                  \
		__uint(type, BPF_MAP_TYPE_ARRAY); \
		__type(key, __u32);               \
		__type(value, struct pkt_count);  \
		__uint(max_entries, 1);           \
		__uint(pinning, 1);               \
	} count_map SEC(".maps");

#define LATENCY_START_TIMESTAMP_DEFINE \
	__u64 start_timestamp = bpf_ktime_get_ns();

#define PACKET_COUNT_MAP_UPDATE                                    \
	{                                                          \
		u32 __index = 0;                                   \
		struct pkt_count *current_count =                  \
			bpf_map_lookup_elem(&count_map, &__index); \
		if (current_count == NULL) {                       \
			return XDP_DROP;                           \
		}                                                  \
		__u64 end_timestamp = bpf_ktime_get_ns();          \
		__u64 duration = end_timestamp - start_timestamp;  \
		current_count->rx_count += 1;                      \
		current_count->lat_count += duration;              \
	}

#define ETH_ALEN 6
#define SWAP_MAC_AND_RETURN_XDP_TX(cxt)                                       \
	struct ethhdr *eth_tx = (void *)(long)ctx->data;                      \
	if ((void *)eth_tx + sizeof(*eth_tx) > (void *)(long)ctx->data_end) { \
		return XDP_DROP;                                              \
	}                                                                     \
	unsigned char temp[ETH_ALEN];                                         \
	/* 交换源MAC和目的MAC地址 */                                  \
	__builtin_memcpy(temp, eth_tx->h_source, ETH_ALEN);                   \
	__builtin_memcpy(eth_tx->h_source, eth_tx->h_dest, ETH_ALEN);         \
	__builtin_memcpy(eth_tx->h_dest, temp, ETH_ALEN);                     \
	return XDP_TX;\
