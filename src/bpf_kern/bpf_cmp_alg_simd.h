#ifndef _BPF_CMP_ALG_SIMD_H
#define _BPF_CMP_ALG_SIMD_H

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

/**
 * bpf_find_u32_avx() - Find 32-bit value in array of 8 32-bit values.
 *
 * @arr: Pointer to at least 8 32-bit values.
 * @val: Value to find in the array.
 *
 * Return: index of value; 8 if not found
 */
extern u32 bpf_find_u32_avx(const u32 *arr, u32 val) __ksym;

/**
 * bpf_find_u16_avx() - Find 16-bit value in array of 16 16-bit values.
 *
 * @arr: Pointer to at least 16 16-bit values.
 * @val: Value to find in the array.
 *
 * Return: index of value; 16 if not found
 */
extern u32 bpf_find_u16_avx(const u16 *arr, u16 val) __ksym;

/**
 * bpf_find_u16_sse() - Find 16-bit value in array of 8 16-bit values.
 *
 * @arr: Pointer to at least 8 16-bit values.
 * @val: Value to find in the array.
 *
 * Return: index of value; 8 if not found
 */
extern u32 bpf_find_u16_sse(const u16 *arr, u16 val) __ksym;

/**
 * bpf__find_mask_u32_avx() - Find 32-bit value in array of 8 32-bit values.
 *
 * @arr: Pointer to at least 8 32-bit values.
 * @val: Value to find in the array.
 *
 * Return: 32-bit mask
 */
extern u32 bpf__find_mask_u32_avx(const u32 *arr, u32 val) __ksym;

/**
 * bpf__find_mask_u16_avx() - Find 16-bit value in array of 16 16-bit values.
 *
 * @arr: Pointer to at least 16 16-bit values.
 * @val: Value to find in the array.
 *
 * Return: 32-bit mask
 */
extern u32 bpf__find_mask_u16_avx(const u16 *arr, u16 val) __ksym;

/**
 * bpf__find_mask_u16_sse() - Find 16-bit value in array of 8 16-bit values.
 *
 * @arr: Pointer to at least 8 16-bit values.
 * @val: Value to find in the array.
 *
 * Return: 16-bit mask
 */
extern u32 bpf__find_mask_u16_sse(const u16 *arr, u16 val) __ksym;

/**
 * bpf_find_mask_u32_avx() - Find 32-bit value in array of 8 32-bit values.
 *
 * @arr: Pointer to at least 8 32-bit values.
 * @val: Value to find in the array.
 *
 * Return: 8-bit mask
 */
extern u32 bpf_find_mask_u32_avx(const u32 *arr, u32 val) __ksym;

/**
 * bpf_find_mask_u16_avx() - Find 32-bit value in array of 16 16-bit values.
 *
 * @arr: Pointer to at least 16 16-bit values.
 * @val: Value to find in the array.
 *
 * Return: 16-bit mask
 */
extern u32 bpf_find_mask_u16_avx(const u16 *arr, u16 val) __ksym;

/**
 * bpf_find_mask_u32_sse() - Find 32-bit value in array of 8 16-bit values.
 *
 * @arr: Pointer to at least 8 16-bit values.
 * @val: Value to find in the array.
 *
 * Return: 8-bit mask
 */
extern u32 bpf_find_mask_u16_sse(const u16 *arr, u16 val) __ksym;

/**
 * bpf_tzcnt_u32() - Count trailing zero bits in 32-bit value.
 *
 * @val: 32-bit value
 *
 * Return: number of trailing zero bits
 */
extern u32 bpf_tzcnt_u32(u32 val) __ksym;

/**
 * bpf_tzcnt_u16() - Count trailing zero bits in 16-bit value.
 *
 * @val: 16-bit value
 *
 * Return: number of trailing zero bits
 */
extern u32 bpf_tzcnt_u16(u16 val) __ksym;

/**
 * bpf_find_min_u32_avx() - Find minimum value in array of 8 16-bit values.
 *
 * @arr: Pointer to at least 8 32-bit values.
 *
 * Return: index of minimum value
 */
extern u32 bpf_find_min_u16_sse(const u16 *arr) __ksym;

/**
 * bpf_k16_cmp_eq() - Compare two 16-byte values for equality.
 *
 * @key1: Pointer to first 16-byte value.
 * @key1__sz: Size of first 16-byte value (should be greater or equal to 16).
 * @key2: Pointer to second 16-byte value.
 * @key2__sz: Size of second 16-byte value (should be greater or equal to 16).
 *
 * Return: 1 if equal, 0 otherwise
 */
extern int bpf_k16_cmp_eq(const void *key1, size_t key1__sz, const void *key2,
			  size_t key2__sz) __ksym;

/**
 * bpf_k32_cmp_eq() - Compare two 32-byte values for equality.
 *
 * @key1: Pointer to first 32-byte value.
 * @key1__sz: Size of first 32-byte value (should be greater or equal to 32).
 * @key2: Pointer to second 32-byte value.
 * @key2__sz: Size of second 32-byte value (should be greater or equal to 32).
 *
 * Return: 1 if equal, 0 otherwise
 */
extern int bpf_k32_cmp_eq(const void *key1, size_t key1__sz, const void *key2,
			  size_t key2__sz) __ksym;

/**
 * bpf_mm256_cmpeq_epi32() - Call _mm256_cmpeq_epi32 intrinsic.
 *
 * @arr: Pointer to 256-bit vector.
 * @val: 32-bit value to compare against.
 * @dest: Pointer to 256-bit vector to store result.
 */
extern void bpf_mm256_cmpeq_epi32(const u32 *arr, u32 val, u32 *dest) __ksym;

/**
 * bpf_mm256_cmpeq_epi16() - Call _mm256_cmpeq_epi16 intrinsic.
 *
 * @arr: Pointer to 256-bit vector.
 * @val: 16-bit value to compare against.
 * @dest: Pointer to 256-bit vector to store result.
 */
extern void bpf_mm256_cmpeq_epi16(const u16 *arr, u16 val, u16 *dest) __ksym;

/**
 * bpf_mm256_movemask_epi8() - Call _mm256_movemask_epi8 intrinsic.
 *
 * @arr: Pointer to 256-bit vector.
 *
 * Return: 32-bit mask
 */
extern u32 bpf_mm256_movemask_epi8(const u8 *arr) __ksym;

#define __for_each_u32_avx(idx, mask, delta)              \
	(delta) = bpf_tzcnt_u32(mask);                    \
	(mask) >>= (delta);                               \
	for ((idx) = ((delta) >> 2); (idx) < 8 && (mask); \
	     (mask) >> 4, (idx) += 1)                     \
		if ((mask)&0x01)

#define for_each_u32_avx(arr, val, idx, mask, delta)  \
	(mask) = bpf_find_mask_u32_avx((arr), (val)); \
	__for_each_u32_avx((idx), (mask), (delta))

#define __for_each_u16_avx(idx, mask, delta)               \
	(delta) = bpf_tzcnt_u32(mask);                     \
	(mask) >>= (delta);                                \
	for ((idx) = ((delta) >> 1); (idx) < 16 && (mask); \
	     (mask) >>= 2, (idx) += 1)                     \
		if ((mask)&0x01)

#define for_each_u16_avx(arr, val, idx, mask, delta)   \
	(mask) = bpf__find_mask_u16_avx((arr), (val)); \
	__for_each_u16_avx((idx), (mask), (delta))

#define __for_each_u16_sse(idx, mask, delta)              \
	(delta) = bpf_tzcnt_u16(mask);                    \
	(mask) >>= (delta);                               \
	for ((idx) = ((delta) >> 1); (idx) < 8 && (mask); \
	     (mask) >>= 2, (idx) += 1)                    \
		if ((mask)&0x01)

#define for_each_u16_sse(arr, val, idx, mask, delta)   \
	(mask) = bpf__find_mask_u16_sse((arr), (val)); \
	__for_each_u16_sse((idx), (mask), (delta))
#endif
