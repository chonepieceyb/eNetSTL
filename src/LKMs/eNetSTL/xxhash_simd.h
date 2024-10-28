#ifndef XXHASH_SIMD_H
#define XXHASH_SIMD_H

#if defined(__x86_64) || defined(__i386)
#include "xxhash_x86.h"
#else
#error "Unsupported architecture"
#endif

#endif /* XXHASH_SIMD_H */
