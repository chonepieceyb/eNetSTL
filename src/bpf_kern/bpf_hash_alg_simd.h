#ifndef _BPF_HASH_ALG_SIMD_H
#define _BPF_HASH_ALG_SIMD_H

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

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

#endif
