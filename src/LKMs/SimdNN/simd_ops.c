#include "simd_ops.h"
#include <linux/string.h>
#include <linux/log2.h>

/* Constants for hash operations */
static const uint32_t HASH_PRIME_1 = 2654435761U;
static const uint32_t HASH_PRIME_2 = 2246822519U;
static const uint32_t HASH_PRIME_3 = 3266489917U;
static const uint32_t HASH_PRIME_4 = 668265263U;
static const uint32_t HASH_PRIME_5 = 374761393U;

/* AVX2 constants */
static __m256i hash_prime1_vec, hash_prime2_vec, hash_prime3_vec;
static __m256i hash_prime4_vec, hash_prime5_vec;

/**
 * simd_init - Initialize SIMD operations and constants
 */
int simd_init(void)
{
    /* Initialize hash prime vectors */
    hash_prime1_vec = _mm256_set1_epi32(HASH_PRIME_1);
    hash_prime2_vec = _mm256_set1_epi32(HASH_PRIME_2);
    hash_prime3_vec = _mm256_set1_epi32(HASH_PRIME_3);
    hash_prime4_vec = _mm256_set1_epi32(HASH_PRIME_4);
    hash_prime5_vec = _mm256_set1_epi32(HASH_PRIME_5);

    return 0;
}

/**
 * simd_cleanup - Cleanup SIMD operations
 */
void simd_cleanup(void)
{
    /* Nothing to cleanup for now */
}

/**
 * simd_get_supported_type - Get supported SIMD type
 */
simd_type_t simd_get_supported_type(void)
{
#ifdef __AVX2__
    return SIMD_AVX2;
#elif defined(__SSE4_2__)
    return SIMD_SSE42;
#elif defined(__ARM_NEON)
    return SIMD_NEON;
#else
    return SIMD_NONE;
#endif
}

/**
 * simd_avx2_parallel_hash - Compute multiple hashes in parallel using AVX2
 */
void simd_avx2_parallel_hash(const void *data, const uint32_t *seeds,
                           int hash_count, uint32_t *output)
{
    const uint8_t *p = (const uint8_t *)data;
    int i;

    if (hash_count <= 0 || !data || !seeds || !output)
        return;

    /* Process 8 hashes at a time using AVX2 */
    for (i = 0; i < hash_count; i += 8) {
        int batch_size = min(8, hash_count - i);
        __m256i hash_vec;

        /* Load seeds for this batch */
        if (batch_size == 8) {
            hash_vec = _mm256_loadu_si256((const __m256i *)&seeds[i]);
        } else {
            /* Handle partial batch */
            uint32_t seed_batch[8] = {0};
            memcpy(seed_batch, &seeds[i], batch_size * sizeof(uint32_t));
            hash_vec = _mm256_loadu_si256((const __m256i *)seed_batch);
        }

        /* Simple hash computation */
        hash_vec = _mm256_add_epi32(hash_vec, hash_prime5_vec);
        hash_vec = _mm256_xor_si256(hash_vec, _mm256_set1_epi32(*p));
        hash_vec = _mm256_mullo_epi32(hash_vec, hash_prime1_vec);
        hash_vec = _mm256_xor_si256(hash_vec, _mm256_srli_epi32(hash_vec, 16));

        /* Store results */
        if (batch_size == 8) {
            _mm256_storeu_si256((__m256i *)&output[i], hash_vec);
        } else {
            uint32_t result_batch[8];
            _mm256_storeu_si256((__m256i *)result_batch, hash_vec);
            memcpy(&output[i], result_batch, batch_size * sizeof(uint32_t));
        }
    }
}

/**
 * simd_avx2_vector_search - Search for value in vector using SIMD
 */
int simd_avx2_vector_search(const uint16_t *vector, int vector_size, uint16_t value)
{
    int i;

    if (!vector || vector_size <= 0)
        return -1;

    /* Process 16 elements at a time using AVX2 */
    for (i = 0; i < vector_size; i += 16) {
        int batch_size = min(16, vector_size - i);
        __m256i vec_data, vec_value, cmp_result;
        int mask;

        /* Load vector data */
        if (batch_size == 16) {
            vec_data = _mm256_loadu_si256((const __m256i *)&vector[i]);
        } else {
            /* Handle partial batch */
            uint16_t data_batch[16] = {0};
            memcpy(data_batch, &vector[i], batch_size * sizeof(uint16_t));
            vec_data = _mm256_loadu_si256((const __m256i *)data_batch);
        }

        /* Compare with target value */
        vec_value = _mm256_set1_epi16(value);
        cmp_result = _mm256_cmpeq_epi16(vec_data, vec_value);
        mask = _mm256_movemask_epi8(cmp_result);

        /* Check if any match */
        if (mask != 0) {
            return i + __builtin_ctz(mask) / 2;
        }
    }

    return -1;
}

/**
 * simd_avx2_vector_count - Count occurrences of value in vector using SIMD
 */
int simd_avx2_vector_count(const uint16_t *vector, int vector_size, uint16_t value)
{
    int i, count = 0;

    if (!vector || vector_size <= 0)
        return 0;

    /* Process 16 elements at a time using AVX2 */
    for (i = 0; i < vector_size; i += 16) {
        int batch_size = min(16, vector_size - i);
        __m256i vec_data, vec_value, cmp_result;
        int mask;

        /* Load vector data */
        if (batch_size == 16) {
            vec_data = _mm256_loadu_si256((const __m256i *)&vector[i]);
        } else {
            /* Handle partial batch */
            uint16_t data_batch[16] = {0};
            memcpy(data_batch, &vector[i], batch_size * sizeof(uint16_t));
            vec_data = _mm256_loadu_si256((const __m256i *)data_batch);
        }

        /* Compare with target value */
        vec_value = _mm256_set1_epi16(value);
        cmp_result = _mm256_cmpeq_epi16(vec_data, vec_value);
        mask = _mm256_movemask_epi8(cmp_result);

        /* Count matches */
        count += __builtin_popcount(mask) / 2;
    }

    return count;
}

/**
 * simd_avx2_relu - ReLU activation function using SIMD
 */
void simd_avx2_relu(const float *input, float *output, int size)
{
    int i;

    if (!input || !output || size <= 0)
        return;

    /* Process 8 elements at a time using AVX2 */
    for (i = 0; i < size; i += 8) {
        int batch_size = min(8, size - i);
        __m256 input_vec, output_vec;

        /* Load input data */
        if (batch_size == 8) {
            input_vec = _mm256_loadu_ps(&input[i]);
        } else {
            /* Handle partial batch */
            float data_batch[8] = {0};
            memcpy(data_batch, &input[i], batch_size * sizeof(float));
            input_vec = _mm256_loadu_ps(data_batch);
        }

        /* Apply ReLU: max(0, x) */
        output_vec = _mm256_max_ps(input_vec, _mm256_setzero_ps());

        /* Store results */
        if (batch_size == 8) {
            _mm256_storeu_ps(&output[i], output_vec);
        } else {
            float result_batch[8];
            _mm256_storeu_ps(result_batch, output_vec);
            memcpy(&output[i], result_batch, batch_size * sizeof(float));
        }
    }
}

/**
 * simd_avx2_sigmoid - Sigmoid activation function using SIMD
 */
void simd_avx2_sigmoid(const float *input, float *output, int size)
{
    int i;

    if (!input || !output || size <= 0)
        return;

    /* Process 8 elements at a time using AVX2 */
    for (i = 0; i < size; i += 8) {
        int batch_size = min(8, size - i);
        __m256 input_vec, output_vec;

        /* Load input data */
        if (batch_size == 8) {
            input_vec = _mm256_loadu_ps(&input[i]);
        } else {
            /* Handle partial batch */
            float data_batch[8] = {0};
            memcpy(data_batch, &input[i], batch_size * sizeof(float));
            input_vec = _mm256_loadu_ps(data_batch);
        }

        /* Approximate sigmoid: 1 / (1 + exp(-x))
         * Using polynomial approximation for performance */
        __m256 neg_input = _mm256_mul_ps(input_vec, _mm256_set1_ps(-1.0f));
        __m256 exp_neg = _mm256_rcp_ps(_mm256_add_ps(_mm256_set1_ps(1.0f),
                                                     _mm256_mul_ps(neg_input, neg_input)));
        output_vec = _mm256_mul_ps(_mm256_set1_ps(0.5f), exp_neg);

        /* Store results */
        if (batch_size == 8) {
            _mm256_storeu_ps(&output[i], output_vec);
        } else {
            float result_batch[8];
            _mm256_storeu_ps(result_batch, output_vec);
            memcpy(&output[i], result_batch, batch_size * sizeof(float));
        }
    }
}

/**
 * simd_avx2_tanh - Hyperbolic tangent activation function using SIMD
 */
void simd_avx2_tanh(const float *input, float *output, int size)
{
    int i;

    if (!input || !output || size <= 0)
        return;

    /* Process 8 elements at a time using AVX2 */
    for (i = 0; i < size; i += 8) {
        int batch_size = min(8, size - i);
        __m256 input_vec, output_vec;

        /* Load input data */
        if (batch_size == 8) {
            input_vec = _mm256_loadu_ps(&input[i]);
        } else {
            /* Handle partial batch */
            float data_batch[8] = {0};
            memcpy(data_batch, &input[i], batch_size * sizeof(float));
            input_vec = _mm256_loadu_ps(data_batch);
        }

        /* Approximate tanh using polynomial approximation */
        __m256 x2 = _mm256_mul_ps(input_vec, input_vec);
        __m256 x3 = _mm256_mul_ps(x2, input_vec);
        __m256 x5 = _mm256_mul_ps(x3, x2);
        __m256 x7 = _mm256_mul_ps(x5, x2);

        /* Taylor series approximation: x - x^3/3 + 2x^5/15 - 17x^7/315 */
        output_vec = _mm256_sub_ps(input_vec,
                                  _mm256_mul_ps(x3, _mm256_set1_ps(0.333333f)));
        output_vec = _mm256_add_ps(output_vec,
                                  _mm256_mul_ps(x5, _mm256_set1_ps(0.133333f)));
        output_vec = _mm256_sub_ps(output_vec,
                                  _mm256_mul_ps(x7, _mm256_set1_ps(0.053968f)));

        /* Clamp to [-1, 1] */
        output_vec = _mm256_max_ps(output_vec, _mm256_set1_ps(-1.0f));
        output_vec = _mm256_min_ps(output_vec, _mm256_set1_ps(1.0f));

        /* Store results */
        if (batch_size == 8) {
            _mm256_storeu_ps(&output[i], output_vec);
        } else {
            float result_batch[8];
            _mm256_storeu_ps(result_batch, output_vec);
            memcpy(&output[i], result_batch, batch_size * sizeof(float));
        }
    }
}

/**
 * simd_avx2_dot_product - Dot product using SIMD
 */
float simd_avx2_dot_product(const float *a, const float *b, int size)
{
    int i;
    __m256 sum_vec = _mm256_setzero_ps();

    if (!a || !b || size <= 0)
        return 0.0f;

    /* Process 8 elements at a time using AVX2 */
    for (i = 0; i < size; i += 8) {
        int batch_size = min(8, size - i);
        __m256 a_vec, b_vec, product_vec;

        /* Load vectors */
        if (batch_size == 8) {
            a_vec = _mm256_loadu_ps(&a[i]);
            b_vec = _mm256_loadu_ps(&b[i]);
        } else {
            /* Handle partial batch */
            float a_batch[8] = {0}, b_batch[8] = {0};
            memcpy(a_batch, &a[i], batch_size * sizeof(float));
            memcpy(b_batch, &b[i], batch_size * sizeof(float));
            a_vec = _mm256_loadu_ps(a_batch);
            b_vec = _mm256_loadu_ps(b_batch);
        }

        /* Multiply and accumulate */
        product_vec = _mm256_mul_ps(a_vec, b_vec);
        sum_vec = _mm256_add_ps(sum_vec, product_vec);
    }

    /* Sum all elements */
    alignas(32) float sum_array[8];
    _mm256_store_ps(sum_array, sum_vec);

    float sum = 0.0f;
    for (i = 0; i < 8; i++) {
        sum += sum_array[i];
    }

    return sum;
}

/**
 * simd_avx2_matrix_multiply - Matrix multiplication using SIMD
 */
void simd_avx2_matrix_multiply(const float *a, const float *b, float *c,
                              int m, int n, int k)
{
    int i, j, l;

    if (!a || !b || !c || m <= 0 || n <= 0 || k <= 0)
        return;

    /* Initialize output matrix */
    memset(c, 0, m * n * sizeof(float));

    /* Perform matrix multiplication C = A * B */
    for (i = 0; i < m; i++) {
        for (j = 0; j < n; j++) {
            __m256 sum_vec = _mm256_setzero_ps();
            int remaining = k;

            /* Process 8 elements at a time */
            for (l = 0; l < k; l += 8) {
                int batch_size = min(8, remaining);
                __m256 a_vec, b_vec, product_vec;

                /* Load vectors */
                if (batch_size == 8) {
                    a_vec = _mm256_loadu_ps(&a[i * k + l]);
                    b_vec = _mm256_loadu_ps(&b[l * n + j]);
                } else {
                    /* Handle partial batch */
                    float a_batch[8] = {0}, b_batch[8] = {0};
                    memcpy(a_batch, &a[i * k + l], batch_size * sizeof(float));
                    memcpy(b_batch, &b[l * n + j], batch_size * sizeof(float));
                    a_vec = _mm256_loadu_ps(a_batch);
                    b_vec = _mm256_loadu_ps(b_batch);
                }

                /* Multiply and accumulate */
                product_vec = _mm256_mul_ps(a_vec, b_vec);
                sum_vec = _mm256_add_ps(sum_vec, product_vec);
                remaining -= batch_size;
            }

            /* Sum all elements */
            alignas(32) float sum_array[8];
            _mm256_store_ps(sum_array, sum_vec);

            float sum = 0.0f;
            for (l = 0; l < 8; l++) {
                sum += sum_array[l];
            }

            c[i * n + j] = sum;
        }
    }
}

/* Module initialization and cleanup */
static int __init simd_ops_init(void)
{
    printk(KERN_INFO "SimdNN-SIMD operations module loaded\n");
    return simd_init();
}

static void __exit simd_ops_exit(void)
{
    simd_cleanup();
    printk(KERN_INFO "SimdNN-SIMD operations module unloaded\n");
}

module_init(simd_ops_init);
module_exit(simd_ops_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("eNetSTL Team");
MODULE_DESCRIPTION("SIMD operations for neural network acceleration");
MODULE_VERSION("1.0");