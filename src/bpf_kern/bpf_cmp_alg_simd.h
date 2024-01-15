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

#define for_each_bit_set(idx, mask, delta)                      \
	(delta) = bpf_tzcnt_u32(mask);                          \
	for ((idx) = (delta); (mask); (mask) >>= ((delta) + 1), \
	    (delta) = bpf_tzcnt_u32(mask), (idx) += (delta))

#define for_each_u32_avx(arr, val, idx, mask, delta)  \
	(mask) = bpf_find_mask_u32_avx((arr), (val)); \
	for_each_bit_set((idx), (mask), (delta))

#define for_each_u16_avx(arr, val, idx, mask, delta)  \
	(mask) = bpf_find_mask_u16_avx((arr), (val)); \
	for_each_bit_set((idx), (mask), (delta))

#define for_each_u16_sse(arr, val, idx, mask, delta)  \
	(mask) = bpf_find_mask_u16_sse((arr), (val)); \
	for_each_bit_set((idx), (mask), (delta))

#endif
