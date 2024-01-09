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
 * Return: index of value; -1 if not found
 */
extern u8 bpf_find_u32_avx2(const u32 *arr, u32 val) __ksym;

/**
 * bpf_find_u16_avx2() - Find 16-bit value in array of 16 16-bit values.
 * 
 * @arr: Pointer to at least 16 16-bit values.
 * @val: Value to find in the array.
 * 
 * Return: index of value; -1 if not found
 */
extern u8 bpf_find_u16_avx2(const u16 *arr, u16 val) __ksym;

/**
 * bpf_find_u16_sse2() - Find 16-bit value in array of 8 16-bit values.
 * 
 * @arr: Pointer to at least 8 16-bit values.
 * @val: Value to find in the array.
 * 
 * Return: index of value; -1 if not found
 */
extern u8 bpf_find_u16_sse2(const u16 *arr, u16 val) __ksym;

#endif
