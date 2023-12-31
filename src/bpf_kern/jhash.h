#ifndef _JHASH_H
#define _JHASH_H

#include "common.h"
/*
 * jhash.h
 *
 * Example hash function.
 *
 * Copyright 2009-2012 - Mathieu Desnoyers <mathieu.desnoyers@polymtl.ca>
 *
 * THIS MATERIAL IS PROVIDED AS IS, WITH ABSOLUTELY NO WARRANTY EXPRESSED
 * OR IMPLIED.  ANY USE IS AT YOUR OWN RISK.
 *
 * Permission is hereby granted to use or copy this program for any
 * purpose,  provided the above notices are retained on all copies.
 * Permission to modify the code and to distribute modified code is
 * granted, provided the above notices are retained, and a notice that
 * the code was modified is included with the above copyright notice.
 */

/*
 * Hash function
 * Source: http://burtleburtle.net/bob/c/lookup3.c
 * Originally Public Domain
 */

/* definition of the packet 5 tuple */
struct pkt_5tuple {
  	__be32 src_ip;
  	__be32 dst_ip;
  	__be16 src_port;
  	__be16 dst_port;
  	uint8_t proto;
} __attribute__((packed));

#define rot(x, k) (((x) << (k)) | ((x) >> (32 - (k))))

#define mix(a, b, c) \
do { \
	a -= c; a ^= rot(c,  4); c += b; \
	b -= a; b ^= rot(a,  6); a += c; \
	c -= b; c ^= rot(b,  8); b += a; \
	a -= c; a ^= rot(c, 16); c += b; \
	b -= a; b ^= rot(a, 19); a += c; \
	c -= b; c ^= rot(b,  4); b += a; \
} while (0)

#define final(a, b, c) \
{ \
	c ^= b; c -= rot(b, 14); \
	a ^= c; a -= rot(c, 11); \
	b ^= a; b -= rot(a, 25); \
	c ^= b; c -= rot(b, 16); \
	a ^= c; a -= rot(c,  4); \
	b ^= a; b -= rot(a, 14); \
	c ^= b; c -= rot(b, 24); \
}

#if (BYTE_ORDER == LITTLE_ENDIAN)
#define HASH_LITTLE_ENDIAN	1
#else
#define HASH_LITTLE_ENDIAN	0
#endif

static
__u32 hashlittle_u32(__u32 key, size_t length, __u32 initval)
{
	__u32 a, b, c;	/* internal state */
	__u32 key_copy = key;
	__u32 *key_ptr = &key_copy;
	union {
		const __u32 *ptr;
		size_t i;
	} u;

	/* Set up the internal state */
	a = b = c = 0xdeadbeef + ((__u32)length) + initval;

	u.ptr = key_ptr;
	if (HASH_LITTLE_ENDIAN && ((u.i & 0x3) == 0)) {
		const __u32 *k = (const __u32 *) key_ptr;	/* read 32-bit chunks */

		/*------ all but last block: aligned reads and affect 32 bits of (a,b,c) */
		while (length > 12) {
			a += k[0];
			b += k[1];
			c += k[2];
			mix(a, b, c);
			length -= 12;
			k += 3;
		}

		switch (length) {
		case 12: c+=k[2]; b+=k[1]; a+=k[0]; break;
		case 11: c+=k[2]&0xffffff; b+=k[1]; a+=k[0]; break;
		case 10: c+=k[2]&0xffff; b+=k[1]; a+=k[0]; break;
		case 9 : c+=k[2]&0xff; b+=k[1]; a+=k[0]; break;
		case 8 : b+=k[1]; a+=k[0]; break;
		case 7 : b+=k[1]&0xffffff; a+=k[0]; break;
		case 6 : b+=k[1]&0xffff; a+=k[0]; break;
		case 5 : b+=k[1]&0xff; a+=k[0]; break;
		case 4 : a+=k[0]; break;
		case 3 : a+=k[0]&0xffffff; break;
		case 2 : a+=k[0]&0xffff; break;
		case 1 : a+=k[0]&0xff; break;
		case 0 : return c;		/* zero length strings require no mixing */
		}

	} else {					/* key size smaller than 4Bytes */
		log_error("unexcepted error at %d", __LINE__);
	}

	final(a, b, c);
	return c;
}

static
__u32 jhash_u32(__u32 key, size_t length, __u32 seed)
{
	return hashlittle_u32(key, length, seed);
}

static
__u32 hashlittle_pkt(struct pkt_5tuple key, size_t length, __u32 initval)
{
	__u32 a, b, c;	/* internal state */
	struct pkt_5tuple key_copy = key;
	struct pkt_5tuple *key_ptr = &key_copy;
	union {
		const struct pkt_5tuple *ptr;
		size_t i;
	} u;

	/* Set up the internal state */
	a = b = c = 0xdeadbeef + ((__u32)length) + initval;

	u.ptr = key_ptr;
	if (HASH_LITTLE_ENDIAN && ((u.i & 0x3) == 0)) {
		const __u32 *k = (const __u32 *) key_ptr;	/* read 32-bit chunks */

		/*------ all but last block: aligned reads and affect 32 bits of (a,b,c) */
		while (length > 12) {
			a += k[0];
			b += k[1];
			c += k[2];
			mix(a, b, c);
			length -= 12;
			k += 3;
		}

		switch (length) {
		case 12: c+=k[2]; b+=k[1]; a+=k[0]; break;
		case 11: c+=k[2]&0xffffff; b+=k[1]; a+=k[0]; break;
		case 10: c+=k[2]&0xffff; b+=k[1]; a+=k[0]; break;
		case 9 : c+=k[2]&0xff; b+=k[1]; a+=k[0]; break;
		case 8 : b+=k[1]; a+=k[0]; break;
		case 7 : b+=k[1]&0xffffff; a+=k[0]; break;
		case 6 : b+=k[1]&0xffff; a+=k[0]; break;
		case 5 : b+=k[1]&0xff; a+=k[0]; break;
		case 4 : a+=k[0]; break;
		case 3 : a+=k[0]&0xffffff; break;
		case 2 : a+=k[0]&0xffff; break;
		case 1 : a+=k[0]&0xff; break;
		case 0 : return c;		/* zero length strings require no mixing */
		}

	} else {					/* key size smaller than 4Bytes */
		log_error("unexcepted error at %d", __LINE__);
	}

	final(a, b, c);
	return c;
}

static
__u32 jhash_pkt(struct pkt_5tuple key, size_t length, __u32 seed)
{
	return hashlittle_pkt(key, length, seed);
}

#endif /* _JHASH_H */