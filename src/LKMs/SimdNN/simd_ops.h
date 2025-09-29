#ifndef _SIMD_OPS_H
#define _SIMD_OPS_H

#include <linux/types.h>
#include <linux/kernel.h>
#include <asm/unaligned.h>

#ifdef __clang__
#define __MM_MALLOC_H
#else
#define _MM_MALLOC_H_INCLUDED
#endif

#include <immintrin.h>

/* SIMD operation types */
typedef enum {
    SIMD_AVX2,
    SIMD_SSE42,
    SIMD_NEON,
    SIMD_NONE
} simd_type_t;

/* Common constants for SIMD operations */
#define SIMD_VECTOR_SIZE_256 32
#define SIMD_VECTOR_SIZE_128 16
#define SIMD_LANES_256_32BIT 8
#define SIMD_LANES_256_16BIT 16
#define SIMD_LANES_128_32BIT 4
#define SIMD_LANES_128_16BIT 8

/* AVX2 Operations - 256-bit vectors */

/**
 * simd_avx2_set1_epi32 - Broadcast 32-bit integer to all lanes
 * @value: Integer value to broadcast
 * Return: __m256i vector with all lanes set to value
 */
static inline __m256i simd_avx2_set1_epi32(int value)
{
    return _mm256_set1_epi32(value);
}

/**
 * simd_avx2_set1_epi16 - Broadcast 16-bit integer to all lanes
 * @value: Integer value to broadcast
 * Return: __m256i vector with all lanes set to value
 */
static inline __m256i simd_avx2_set1_epi16(short value)
{
    return _mm256_set1_epi16(value);
}

/**
 * simd_avx2_loadu_si256 - Load unaligned 256-bit data
 * @ptr: Pointer to data to load
 * Return: __m256i vector containing loaded data
 */
static inline __m256i simd_avx2_loadu_si256(const void *ptr)
{
    return _mm256_loadu_si256((const __m256i_u *)ptr);
}

/**
 * simd_avx2_add_epi32 - Add 32-bit integers
 * @a: First vector
 * @b: Second vector
 * Return: __m256i vector with element-wise addition
 */
static inline __m256i simd_avx2_add_epi32(__m256i a, __m256i b)
{
    return _mm256_add_epi32(a, b);
}

/**
 * simd_avx2_mullo_epi32 - Multiply 32-bit integers (lower 32 bits)
 * @a: First vector
 * @b: Second vector
 * Return: __m256i vector with element-wise multiplication
 */
static inline __m256i simd_avx2_mullo_epi32(__m256i a, __m256i b)
{
    return _mm256_mullo_epi32(a, b);
}

/**
 * simd_avx2_xor_si256 - XOR 256-bit integers
 * @a: First vector
 * @b: Second vector
 * Return: __m256i vector with element-wise XOR
 */
static inline __m256i simd_avx2_xor_si256(__m256i a, __m256i b)
{
    return _mm256_xor_si256(a, b);
}

/**
 * simd_avx2_slli_epi32 - Shift left 32-bit integers
 * @a: Vector to shift
 * @count: Number of bits to shift
 * Return: __m256i vector with shifted elements
 */
static inline __m256i simd_avx2_slli_epi32(__m256i a, int count)
{
    return _mm256_slli_epi32(a, count);
}

/**
 * simd_avx2_srli_epi32 - Shift right 32-bit integers
 * @a: Vector to shift
 * @count: Number of bits to shift
 * Return: __m256i vector with shifted elements
 */
static inline __m256i simd_avx2_srli_epi32(__m256i a, int count)
{
    return _mm256_srli_epi32(a, count);
}

/**
 * simd_avx2_cmpeq_epi16 - Compare 16-bit integers for equality
 * @a: First vector
 * @b: Second vector
 * Return: __m256i vector with comparison results (0xFFFF for equal, 0 for not equal)
 */
static inline __m256i simd_avx2_cmpeq_epi16(__m256i a, __m256i b)
{
    return _mm256_cmpeq_epi16(a, b);
}

/**
 * simd_avx2_movemask_epi8 - Create mask from comparison results
 * @a: Vector to create mask from
 * Return: 32-bit integer mask
 */
static inline int simd_avx2_movemask_epi8(__m256i a)
{
    return _mm256_movemask_epi8(a);
}

/**
 * simd_avx2_rotl32 - Rotate left 32-bit integers
 * @a: Vector to rotate
 * @count: Number of bits to rotate
 * Return: __m256i vector with rotated elements
 */
static inline __m256i simd_avx2_rotl32(__m256i a, int count)
{
    return _mm256_or_si256(_mm256_slli_epi32(a, count),
                         _mm256_srli_epi32(a, 32 - count));
}

/* SSE4.2 Operations - 128-bit vectors */

/**
 * simd_sse42_crc32c_u8 - CRC32C checksum for 8-bit data
 * @data: 8-bit input data
 * @init_val: Initial CRC value
 * Return: Updated CRC32C value
 */
static inline uint32_t simd_sse42_crc32c_u8(uint8_t data, uint32_t init_val)
{
    return __builtin_ia32_crc32qi(init_val, data);
}

/**
 * simd_sse42_crc32c_u16 - CRC32C checksum for 16-bit data
 * @data: 16-bit input data
 * @init_val: Initial CRC value
 * Return: Updated CRC32C value
 */
static inline uint32_t simd_sse42_crc32c_u16(uint16_t data, uint32_t init_val)
{
    return __builtin_ia32_crc32hi(init_val, data);
}

/**
 * simd_sse42_crc32c_u32 - CRC32C checksum for 32-bit data
 * @data: 32-bit input data
 * @init_val: Initial CRC value
 * Return: Updated CRC32C value
 */
static inline uint32_t simd_sse42_crc32c_u32(uint32_t data, uint32_t init_val)
{
    return __builtin_ia32_crc32si(init_val, data);
}

/**
 * simd_sse42_crc32c_u64 - CRC32C checksum for 64-bit data
 * @data: 64-bit input data
 * @init_val: Initial CRC value
 * Return: Updated CRC32C value
 */
static inline uint64_t simd_sse42_crc32c_u64(uint64_t data, uint64_t init_val)
{
    return __builtin_ia32_crc32di(init_val, data);
}

/* Hash operations using SIMD */

/**
 * simd_avx2_parallel_hash - Compute multiple hashes in parallel using AVX2
 * @data: Pointer to input data
 * @seeds: Array of seed values (8 seeds for 256-bit vector)
 * @hash_count: Number of hashes to compute
 * @output: Output array for hash results
 */
void simd_avx2_parallel_hash(const void *data, const uint32_t *seeds,
                             int hash_count, uint32_t *output);

/**
 * simd_avx2_vector_search - Search for value in vector using SIMD
 * @vector: Vector to search in
 * @vector_size: Size of the vector
 * @value: Value to search for
 * Return: Index of found value or -1 if not found
 */
int simd_avx2_vector_search(const uint16_t *vector, int vector_size, uint16_t value);

/**
 * simd_avx2_vector_count - Count occurrences of value in vector using SIMD
 * @vector: Vector to search in
 * @vector_size: Size of the vector
 * @value: Value to count
 * Return: Number of occurrences
 */
int simd_avx2_vector_count(const uint16_t *vector, int vector_size, uint16_t value);

/* Neural network specific operations */

/**
 * simd_avx2_relu - ReLU activation function using SIMD
 * @input: Input vector
 * @output: Output vector
 * @size: Size of the vectors
 */
void simd_avx2_relu(const float *input, float *output, int size);

/**
 * simd_avx2_sigmoid - Sigmoid activation function using SIMD
 * @input: Input vector
 * @output: Output vector
 * @size: Size of the vectors
 */
void simd_avx2_sigmoid(const float *input, float *output, int size);

/**
 * simd_avx2_tanh - Hyperbolic tangent activation function using SIMD
 * @input: Input vector
 * @output: Output vector
 * @size: Size of the vectors
 */
void simd_avx2_tanh(const float *input, float *output, int size);

/**
 * simd_avx2_dot_product - Dot product using SIMD
 * @a: First vector
 * @b: Second vector
 * @size: Size of the vectors
 * Return: Dot product result
 */
float simd_avx2_dot_product(const float *a, const float *b, int size);

/**
 * simd_avx2_matrix_multiply - Matrix multiplication using SIMD
 * @a: First matrix
 * @b: Second matrix
 * @c: Output matrix
 * @m: Rows of first matrix
 * @n: Columns of second matrix
 * @k: Common dimension
 */
void simd_avx2_matrix_multiply(const float *a, const float *b, float *c,
                             int m, int n, int k);

/* Utility functions */

/**
 * simd_get_supported_type - Get supported SIMD type
 * Return: simd_type_t indicating supported SIMD type
 */
simd_type_t simd_get_supported_type(void);

/**
 * simd_init - Initialize SIMD operations
 * Return: 0 on success, negative error code on failure
 */
int simd_init(void);

/**
 * simd_cleanup - Cleanup SIMD operations
 */
void simd_cleanup(void);

#endif /* _SIMD_OPS_H */