#pragma once 

#ifdef __KERNEL__
#include <linux/types.h>
#include <asm/rwonce.h>

// This macro is required to include <immtrin.h> in the kernel
#ifdef __clang__
#define __MM_MALLOC_H
#else
#define _MM_MALLOC_H_INCLUDED
#endif

#else
#include <stdint.h>
#include <stdio.h>

typedef uint32_t u32;
typedef uint64_t u64;
#endif

#include <immintrin.h>


struct pkt_5tuple {
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	uint8_t proto;
} __attribute__((packed));