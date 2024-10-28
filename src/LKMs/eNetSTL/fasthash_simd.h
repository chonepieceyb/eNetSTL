#ifndef FASTHASH_SIMD_H
#define FASTHASH_SIMD_H

#if defined(__x86_64) || defined(__i386)
#include "fasthash_x86.h"
#else
#error "Unsupported architecture"
#endif

#endif /* FASTHASH_SIMD_H */
