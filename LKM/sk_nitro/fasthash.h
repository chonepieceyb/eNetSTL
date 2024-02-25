/* The MIT License

   Copyright (C) 2012 Zilong Tan (eric.zltan@gmail.com)

   Permission is hereby granted, free of charge, to any person
   obtaining a copy of this software and associated documentation
   files (the "Software"), to deal in the Software without
   restriction, including without limitation the rights to use, copy,
   modify, merge, publish, distribute, sublicense, and/or sell copies
   of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be
   included in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
   BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
   ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
   CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
*/

#ifndef _FASTHASH_H
#define _FASTHASH_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <stdio.h>

typedef uint32_t u32;
typedef uint64_t u64;
#endif

#define mix(h)                                \
	({                                    \
		(h) ^= (h) >> 23;             \
		(h) *= 0x2127599bf4325c37ULL; \
		(h) ^= (h) >> 47;             \
	})

static __always_inline u64 fasthash64(const void *buf, size_t len, u64 seed)
{
	const u64 m = 0x880355f21e6d1965ULL;
	const u64 *pos = (const u64 *)buf;
	const u64 *end = pos + (len / 8);
	const unsigned char *pos2;
	u64 h = seed ^ (len * m);
	u64 v;

	while (pos != end) {
		v = *pos++;
		h ^= mix(v);
		h *= m;
	}

	pos2 = (const unsigned char *)pos;
	v = 0;

	switch (len & 7) {
	case 7:
		v ^= (u64)pos2[6] << 48;
	case 6:
		v ^= (u64)pos2[5] << 40;
	case 5:
		v ^= (u64)pos2[4] << 32;
	case 4:
		v ^= (u64)pos2[3] << 24;
	case 3:
		v ^= (u64)pos2[2] << 16;
	case 2:
		v ^= (u64)pos2[1] << 8;
	case 1:
		v ^= (u64)pos2[0];
		h ^= mix(v);
		h *= m;
	}

	return mix(h);
}

static __always_inline uint32_t fasthash32(const void *buf, size_t len,
					   uint32_t seed)
{
	// the following trick converts the 64-bit hashcode to Fermat
	// residue, which shall retain information from both the higher
	// and lower parts of hashcode.
	u64 h = fasthash64(buf, len, seed);
	return h - (h >> 32);
}

/*buf should be the sizeof(pkt_5) 13 bytes*/
static __always_inline u64 fasthash64_pkt5(const void *buf, u64 seed)
{
	const u64 m = 0x880355f21e6d1965ULL;
	const u64 *pos = (const u64 *)buf;
	const unsigned char *pos2;
	u64 h = seed ^ (13 * m);
	u64 v;

	/* first 8 bytes */
	v = *pos++;
	h ^= mix(v);
	h *= m;

	pos2 = (const unsigned char *)pos;
	v = 0;

	v ^= (u64)pos2[4] << 32;
	v ^= (u64)pos2[3] << 24;
	v ^= (u64)pos2[2] << 16;
	v ^= (u64)pos2[1] << 8;
	v ^= (u64)pos2[0];
	h ^= mix(v);
	h *= m;
	return mix(h);
}

static __always_inline uint32_t fasthash32_pkt5(const void *buf, uint32_t seed)
{
	// the following trick converts the 64-bit hashcode to Fermat
	// residue, which shall retain information from both the higher
	// and lower parts of hashcode.
	u64 h = fasthash64_pkt5(buf, seed);
	return h - (h >> 32);
}

#endif
