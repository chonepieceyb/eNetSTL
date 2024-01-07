#ifndef _BPF_HASH_ALG_SIMD_H
#define _BPF_HASH_ALG_SIMD_H

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "common.h"
/**
 * bpf_crc32c_sse() - Calculate CRC32 hash on user-supplied byte array.
 *
 * @data: Data to perform hash on.
 * @data__sz: How many bytes to use to calculate hash value.
 * @init_val: Value to initialise hash generator.
 * 
 * Return: 32bit calculated hash value.
 */
extern uint32_t bpf_crc32c_sse(const void *data, uint32_t data__sz,
			       uint32_t init_val) __ksym;

extern void bpf_xxh32_avx2_pkt5(const struct pkt_5tuple *buf, const u32 *seeds,
				u32 *dest) __ksym;
extern void bpf_xxh32_avx2_pkt5_pkts(const u32 *bytes, const u32 seed,
				     u32 *dest) __ksym;
extern void bpf_fasthash32_avx2(const void *buf, size_t buf__sz,
				const u32 *seeds, u32 *dest) __ksym;
extern void bpf_fasthash32_alt_avx2(const void *buf, size_t buf__sz,
				    const u32 *seeds, u32 *dest) __ksym;
extern void bpf_fasthash32_alt_avx2_pkt5(const struct pkt_5tuple *buf,
					 const u32 *seeds, u32 *dest) __ksym;

#endif
