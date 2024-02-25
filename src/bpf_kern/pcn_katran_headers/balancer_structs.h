/* Copyright (C) 2018-present, Facebook, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __BALANCER_STRUCTS_H
#define __BALANCER_STRUCTS_H

/*
 * This file contains description of all structs which has been used both by
 * balancer and by packet's parsing routines
 */

#include "../vmlinux.h"

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif 

struct eth_hdr {
	unsigned char   eth_dest[ETH_ALEN];
	unsigned char   eth_source[ETH_ALEN];
	unsigned short  eth_proto;
};


// flow metadata
struct flow_key {
  __be32 src;
  __be32 dst;
  __u16 port16[2];
  __u8 proto;
};

// client's packet metadata
struct packet_description {
  struct flow_key flow;
  __u32 real_index;
  __u8 flags;
  // dscp / ToS value in client's packet
  __u8 tos;
};

// value for ctl array, could contain e.g. mac address of default router
// or other flags
struct ctl_value {
  __u8 mac[6];
};

// vip's definition for lookup
// struct vip_definition {
//   union {
//     __be32 vip;
//     __be32 vipv6[4];
//   };
//   __u16 port;
//   __u8 proto;
// };

struct vip_definition {
  __be32 vip;
  __u16 port;
  __u8 proto;
};

// result of vip's lookup
struct vip_meta {
  __u32 flags;
  __u32 vip_num;
};

// where to send client's packet from LRU_MAP
struct real_pos_lru {
  __u32 pos;
  __u64 atime;
};

// where to send client's packet from lookup in ch ring.
// struct real_definition {
//   union {
//     __be32 dst;
//     __be32 dstv6[4];
//   };
//   __u8 flags;
// };

struct real_definition {
  __be32 dst;
  __u8 flags;
};

// per vip statistics
struct lb_stats {
  __u64 v1;
  __u64 v2;
};

// key for ipv4 lpm lookups
struct v4_lpm_key {
    __u32 prefixlen;
    __be32 addr;
};

// key for ipv6 lpm lookups
struct v6_lpm_key {
    __u32 prefixlen;
    __be32 addr[4];
};

struct address {
  __be32 addr;
};

#ifdef KATRAN_INTROSPECTION
// metadata about packet, copied to the userspace through event pipe
struct event_metadata {
  __u32 event;
  __u32 pkt_size;
  __u32 data_len;
} __attribute__((__packed__));

#endif
#endif // of _BALANCER_STRUCTS