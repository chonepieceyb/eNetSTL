#ifndef _BPF_CMP_ALG_SIMD_H
#define _BPF_CMP_ALG_SIMD_H

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

/**
 * bpf_find_u32_avx2() - Find 32-bit value in array of 8 32-bit values.
 * 
 * @arr: Pointer to at least 8 32-bit values.
 * @val: Value to find in the array.
 * 
 * Return: index of value; 8 if not found
 */
extern u32 bpf_find_u32_avx2(const u32 *arr, u32 val) __ksym;

/**
 * bpf_find_u16_avx2() - Find 16-bit value in array of 16 16-bit values.
 * 
 * @arr: Pointer to at least 16 16-bit values.
 * @val: Value to find in the array.
 * 
 * Return: index of value; 16 if not found
 */
extern u32 bpf_find_u16_avx2(const u16 *arr, u16 val) __ksym;

/**
 * bpf_find_u16_sse2() - Find 16-bit value in array of 8 16-bit values.
 * 
 * @arr: Pointer to at least 8 16-bit values.
 * @val: Value to find in the array.
 * 
 * Return: index of value; 8 if not found
 */
extern u32 bpf_find_u16_sse2(const u16 *arr, u16 val) __ksym;

/**
 * bpf_find_mask_u32_avx2() - Find 32-bit value in array of 8 32-bit values.
 *
 * @arr: Pointer to at least 8 32-bit values.
 * @val: Value to find in the array.
 *
 * Return: 32-bit mask
 */
extern u32 __bpf_find_mask_u32_avx2(const u32 *arr, u32 val) __ksym;

/**
 * bpf_find_mask_u16_avx2() - Find 16-bit value in array of 16 16-bit values.
 *
 * @arr: Pointer to at least 16 16-bit values.
 * @val: Value to find in the array.
 *
 * Return: 32-bit mask
 */
extern u32 __bpf_find_mask_u16_avx2(const u16 *arr, u16 val) __ksym;

/**
 * bpf_find_mask_u16_sse2() - Find 16-bit value in array of 8 16-bit values.
 *
 * @arr: Pointer to at least 8 16-bit values.
 * @val: Value to find in the array.
 *
 * Return: 16-bit mask
 */
extern u32 __bpf_find_mask_u16_sse2(const u16 *arr, u16 val) __ksym;

/**
 * bpf_find_mask_u32_avx2() - Find 32-bit value in array of 8 32-bit values.
 * 
 * @arr: Pointer to at least 8 32-bit values.
 * @val: Value to find in the array.
 * 
 * Return: 8-bit mask
 */
extern u32 bpf_find_mask_u32_avx2(const u32 *arr, u32 val) __ksym;

/**
 * bpf_find_mask_u16_avx2() - Find 32-bit value in array of 16 16-bit values.
 * 
 * @arr: Pointer to at least 16 16-bit values.
 * @val: Value to find in the array.
 * 
 * Return: 16-bit mask
 */
extern u32 bpf_find_mask_u16_avx2(const u16 *arr, u16 val) __ksym;

/**
 * bpf_find_mask_u32_sse2() - Find 32-bit value in array of 8 16-bit values.
 * 
 * @arr: Pointer to at least 8 16-bit values.
 * @val: Value to find in the array.
 * 
 * Return: 8-bit mask
 */
extern u32 bpf_find_mask_u16_sse2(const u16 *arr, u16 val) __ksym;

static inline u32 __tzcnt_u32_emulated(u32 x)
{
	u32 r = 0;

	if (!x)
		return 32;

	while (!(x & 1)) {
		x >>= 1;
		r++;
	}

	return r;
}

static inline u16 __tzcnt_u16_emulated(u16 x)
{
	u16 r = 0;

	if (!x)
		return 16;

	while (!(x & 1)) {
		x >>= 1;
		r++;
	}

	return r;
}

#define for_each_bit_set(idx, mask, delta)                      \
	(delta) = __tzcnt_u32(mask);                            \
	for ((idx) = (delta); (mask); (mask) >>= ((delta) + 1), \
	    (delta) = __tzcnt_u32(mask), (idx) += (delta))

#define for_each_u32_avx2(arr, val, idx, mask, delta)  \
	(mask) = bpf_find_mask_u32_avx2((arr), (val)); \
	for_each_bit_set((idx), (mask), (delta))

#define for_each_u16_avx2(arr, val, idx, mask, delta)  \
	(mask) = bpf_find_mask_u16_avx2((arr), (val)); \
	for_each_bit_set((idx), (mask), (delta))

#define for_each_u16_sse2(arr, val, idx, mask, delta)  \
	(mask) = bpf_find_mask_u16_sse2((arr), (val)); \
	for_each_bit_set((idx), (mask), (delta))

#endif
