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

#ifndef __BALANCER_HELPERS
#define __BALANCER_HELPERS
/*
 * This file contains common used routines. such as csum helpers etc
 */

#include "../common.h"

#include "balancer_consts.h"
#include "balancer_structs.h"
#include "control_data_maps.h"
#include "csum_helpers.h"
#include "introspection.h"

#ifdef INLINE_DECAP_GENERIC
__attribute__((__always_inline__))
static inline int recirculate(struct xdp_md *ctx, u32 port) {
  pcn_pkt_recircuate(ctx, port);

  pcn_log(ctx, LOG_ERROR, "Recirculate function failed");
  // int i = RECIRCULATION_INDEX;
  // bpf_tail_call(ctx, &subprograms, i);
  // we should never hit this
  // return XDP_PASS;
}
#endif // of INLINE_DECAP_GENERIC

__attribute__((__always_inline__))
static inline int decrement_ttl(void *data, void *data_end, int offset, bool is_ipv6) {
  struct iphdr *iph;
  struct ipv6hdr *ip6h;

  if (is_ipv6) {
    if ((data + offset + sizeof(struct ipv6hdr)) > data_end) {
      return XDP_DROP;
    }
    ip6h = (struct ipv6hdr*)(data + offset);
    if(!--ip6h->hop_limit) {
      // ttl 0
      return XDP_DROP;
    }
  } else {
    if ((data + offset + sizeof(struct iphdr)) > data_end) {
      return XDP_DROP;
    }
    iph = (struct iphdr*)(data + offset);
    __u32 csum;
    if (!--iph->ttl) {
      // ttl 0
      return XDP_DROP;
    }
    csum = iph->check + 0x0001;
    iph->check = (csum & 0xffff) + (csum >> 16);
  }
  return FURTHER_PROCESSING;
}

#endif