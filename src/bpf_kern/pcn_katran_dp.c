/*
 * Copyright 2004-present Facebook. All Rights Reserved.
 * This is main balancer's application code
 */

/*copy from https://github.com/Morpheus-compiler/polycube/blob/c5bb0b060f89cd165e394bf0df936ab99220250d/src/services/pcn-katran/src/Katran_dp.c*/
/*rewrite by chonepieceyb*/

#include "./common.h"
char _license[] SEC("license") = "GPL";
#define _FAKE_LRU_SIZE_PLACEHOLDER_ 1024
#define _DEFAULT_LRU_SIZE_PLACEHOLDER_ 1024

#define FAKE_LRU_SIZE _FAKE_LRU_SIZE_PLACEHOLDER_
#define DEFAULT_LRU_SIZE _DEFAULT_LRU_SIZE_PLACEHOLDER_

#include "./pcn_katran_headers/balancer_consts.h"
#include "./pcn_katran_headers/balancer_helpers.h"
#include "./pcn_katran_headers/balancer_structs.h"
#include "./pcn_katran_headers/balancer_maps.h"
#include "./pcn_katran_headers/pckt_encap.h"
#include "./pcn_katran_headers/pckt_parsing.h"
#include "./pcn_katran_headers/handle_icmp.h"
#include "./pcn_katran_headers/jhash.h"

#define CTXTYPE xdp_md

#define USE_EBPF_MAP 1

__attribute__((__always_inline__))
static inline __u32 get_packet_hash(struct packet_description *pckt,
                                    bool hash_16bytes) {
    __u32 ports = ((__u32)pckt->flow.port16[0] << 16) | ((__u32)pckt->flow.port16[1]);
    return jhash_2words(pckt->flow.src, ports, INIT_JHASH_SEED);
}

__attribute__((__always_inline__))
static inline bool is_under_flood(__u64 *cur_time) {
  __u32 conn_rate_key = MAX_VIPS + NEW_CONN_RATE_CNTR;
  //struct lb_stats *conn_rate_stats = stats.lookup(&conn_rate_key);
  /*data strcuture1*/
  struct lb_stats *conn_rate_stats = bpf_map_lookup_elem(&stats, &conn_rate_key);
  if (!conn_rate_stats) {
    return true;
  }
  *cur_time = bpf_ktime_get_ns();
  // we are going to check that new connections rate is less than predefined
  // value; conn_rate_stats.v1 contains number of new connections for the last
  // second, v2 - when last time quanta started.
  if ((*cur_time - conn_rate_stats->v2) > ONE_SEC) {
    // new time quanta; reseting counters
    conn_rate_stats->v1 = 1;
    conn_rate_stats->v2 = *cur_time;
  } else {
    conn_rate_stats->v1 += 1;
    if (conn_rate_stats->v1 > MAX_CONN_RATE) {
      // we are exceding max connections rate. bypasing lru update and
      // source routing lookup
      return true;
    }
  }
  return false;
}

__attribute__((__always_inline__))
static inline bool get_packet_dst(struct CTXTYPE *ctx,
                                  struct real_definition **real,
                                  struct packet_description *pckt,
                                  struct vip_meta *vip_info,
                                  bool is_ipv6,
                                  void *lru_map) {
  //pcn_log(ctx, LOG_TRACE, "Get packet dst");
  //pcn_log(ctx, LOG_TRACE, "Current session info: IPsrc: %I, IPdst: %I", pckt->flow.src, pckt->flow.dst);
  //pcn_log(ctx, LOG_TRACE, "Port SRC: %u, Port DST: %u, Proto: %u", bpf_ntohs(pckt->flow.port16[0]), bpf_ntohs(pckt->flow.port16[1]), pckt->flow.proto);

  // to update lru w/ new connection
  struct real_pos_lru new_dst_lru = {};
  bool under_flood = false;
  bool src_found = false;
  __u32 *real_pos;
  __u64 cur_time = 0;
  __u32 hash;
  __u32 key;

  under_flood = is_under_flood(&cur_time);

  #ifdef LPM_SRC_LOOKUP
  if ((vip_info->flags & F_SRC_ROUTING) && !under_flood) {
    __u32 *lpm_val;
    if (is_ipv6) {
      struct v6_lpm_key lpm_key_v6 = {};
      lpm_key_v6.prefixlen = 128;
      memcpy(lpm_key_v6.addr, pckt->flow.srcv6, 16);
      lpm_val = lpm_src_v6.lookup(&lpm_key_v6);
    } else {
      struct v4_lpm_key lpm_key_v4 = {};
      lpm_key_v4.addr = pckt->flow.src;
      lpm_key_v4.prefixlen = 32;
      lpm_val = lpm_src_v4.lookup(&lpm_key_v4);
    }
    if (lpm_val) {
      src_found = true;
      key = *lpm_val;
    }
    __u32 stats_key = MAX_VIPS + LPM_SRC_CNTRS;
    struct lb_stats *data_stats = stats.lookup(&stats_key);
    if (data_stats) {
      if (src_found) {
        data_stats->v2 += 1;
      } else {
        data_stats->v1 += 1;
      }
    }
  }
  #endif
  if (!src_found) {
    bool hash_16bytes = is_ipv6;

    if (vip_info->flags & F_HASH_DPORT_ONLY) {
      // service which only use dst port for hash calculation
      // e.g. if packets has same dst port -> they will go to the same real.
      // usually VoIP related services.
      pckt->flow.port16[0] = pckt->flow.port16[1];
      // memset(pckt->flow.srcv6, 0, 16);
    }
    hash = get_packet_hash(pckt, hash_16bytes) % RING_SIZE;
    key = RING_SIZE * (vip_info->vip_num) + hash;
    //pcn_log(ctx, LOG_TRACE, "Lookup real pos in ch_rings with key: %u", key);

    //real_pos = ch_rings.lookup(&key);
    /*data structure 2*/
    real_pos = bpf_map_lookup_elem(&ch_rings, &key);
    if(!real_pos) {
      return false;
    }
    key = *real_pos;
  }
  pckt->real_index = key;
  /*the most important data structure*/
  //*real = reals.lookup(&key);
  *real = bpf_map_lookup_elem(&reals, &key);
  if (!(*real)) {
    return false;
  }
  if (!(vip_info->flags & F_LRU_BYPASS) && !under_flood) {
    new_dst_lru.pos = key;

   // pcn_log(ctx, LOG_TRACE, "Adding entry in lru map for this flow with real pos: %u", key);
    //bpf_map_update_elem_((uintptr_t)lru_map, &pckt->flow, &new_dst_lru, BPF_ANY);
    bpf_map_update_elem(lru_map, &pckt->flow, &new_dst_lru, BPF_ANY); /* !!! have bug here, unexpected & before lru_map */
  }
  return true;
}

__attribute__((__always_inline__))
static inline int process_l3_headers(struct packet_description *pckt,
                                     __u8 *protocol, __u64 off,
                                     __u16 *pkt_bytes, void *data,
                                     void *data_end, bool is_ipv6) {
  __u64 iph_len;
  int action;
  struct iphdr *iph;
  iph = data + off;
  if ((void*)(iph + 1) > data_end) {
    return XDP_DROP;
  }
  //ihl contains len of ipv4 header in 32bit words
  if (iph->ihl != 5) {
    // if len of ipv4 hdr is not equal to 20bytes that means that header
    // contains ip options, and we dont support em
    return XDP_DROP;
  }
  pckt->tos = iph->tos;
  *protocol = iph->protocol;
  pckt->flow.proto = *protocol;
  *pkt_bytes = bpf_ntohs(iph->tot_len);
  off += IPV4_HDR_LEN_NO_OPT;

  if (iph->frag_off & PCKT_FRAGMENTED) {
    // we drop fragmented packets.
    return XDP_DROP;
  }
  if (*protocol == IPPROTO_ICMP) {
    action = parse_icmp(data, data_end, off, pckt);
    if (action >= 0) {
      return action;
    }
  } else {
    pckt->flow.src = iph->saddr;
    pckt->flow.dst = iph->daddr;
  }
  return FURTHER_PROCESSING;
}

#ifdef INLINE_DECAP_GENERIC
__attribute__((__always_inline__))
static inline int check_decap_dst(struct packet_description *pckt,
                                  bool is_ipv6, bool *pass) {
    struct address dst_addr = {};
    struct lb_stats *data_stats;

    if (is_ipv6) {
      memcpy(dst_addr.addrv6, pckt->flow.dstv6, 16);
    } else {
      dst_addr.addr = pckt->flow.dst;
    }
    __u32 *decap_dst_flags = decap_dst.lookup(&dst_addr);

    if (decap_dst_flags) {
      *pass = false;
      __u32 stats_key = MAX_VIPS + REMOTE_ENCAP_CNTRS;
      data_stats = stats.lookup(&stats_key);
      if (!data_stats) {
        return XDP_DROP;
      }
      data_stats->v1 += 1;
    }
    return FURTHER_PROCESSING;
}

#endif // of INLINE_DECAP_GENERIC

#ifdef INLINE_DECAP_IPIP
__attribute__((__always_inline__))
static inline int process_encaped_ipip_pckt(void **data, void **data_end,
                                            struct CTXTYPE *xdp, bool *is_ipv6,
                                            __u8 *protocol, bool pass) {
  int action;
  if (*protocol == IPPROTO_IPIP) {
    if (*is_ipv6) {
      int offset = sizeof(struct ipv6hdr) + sizeof(struct eth_hdr);
      if ((*data + offset) > *data_end) {
        return XDP_DROP;
      }
      action = decrement_ttl(*data, *data_end, offset, false);
      if (!decap_v6(xdp, data, data_end, true)) {
        return XDP_DROP;
      }
      *is_ipv6 = false;
    } else {
      int offset = sizeof(struct iphdr) + sizeof(struct eth_hdr);
      if ((*data + offset) > *data_end) {
        return XDP_DROP;
      }
      action = decrement_ttl(*data, *data_end, offset, false);
      if (!decap_v4(xdp, data, data_end)) {
        return XDP_DROP;
      }
    }
  } else if (*protocol == IPPROTO_IPV6) {
    int offset = sizeof(struct ipv6hdr) + sizeof(struct eth_hdr);
    if ((*data + offset) > *data_end) {
      return XDP_DROP;
    }
    action = decrement_ttl(*data, *data_end, offset, true);
    if (!decap_v6(xdp, data, data_end, false)) {
      return XDP_DROP;
    }
  }
  if (action >= 0) {
    return action;
  }
  if (pass) {
    // pass packet to kernel after decapsulation
    return XDP_PASS;
  }
  return recirculate(xdp);
}
#endif // of INLINE_DECAP_IPIP

#ifdef INLINE_DECAP_GUE
__attribute__((__always_inline__))
static inline int process_encaped_gue_pckt(void **data, void **data_end,
                                           struct CTXTYPE *xdp, bool is_ipv6,
                                           bool pass) {
  int offset = 0;
  int action;
  if (is_ipv6) {
    __u8 v6 = 0;
    offset = sizeof(struct ipv6hdr) + sizeof(struct eth_hdr) +
      sizeof(struct udphdr);
    // 1 byte for gue v1 marker to figure out what is internal protocol
    if ((*data + offset + 1) > *data_end) {
      return XDP_DROP;
    }
    v6 = ((__u8*)(*data))[offset];
    v6 &= GUEV1_IPV6MASK;
    if (v6) {
      // inner packet is ipv6 as well
      action = decrement_ttl(*data, *data_end, offset, true);
      if (!gue_decap_v6(xdp, data, data_end, false)) {
        return XDP_DROP;
      }
    } else {
      // inner packet is ipv4
      action = decrement_ttl(*data, *data_end, offset, false);
      if (!gue_decap_v6(xdp, data, data_end, true)) {
        return XDP_DROP;
      }
    }
  } else {
    offset = sizeof(struct iphdr) + sizeof(struct eth_hdr) +
      sizeof(struct udphdr);
    if ((*data + offset) > *data_end) {
      return XDP_DROP;
    }
    action = decrement_ttl(*data, *data_end, offset, false);
    if (!gue_decap_v4(xdp, data, data_end)) {
        return XDP_DROP;
    }
  }
  if (action >= 0) {
    return action;
  }
  if (pass) {
    return XDP_PASS;
  }
  return recirculate(xdp);
}
#endif // of INLINE_DECAP_GUE

__attribute__((__always_inline__)) static inline void
increment_quic_cid_version_stats(int host_id) {
  __u32 quic_version_stats_key = MAX_VIPS + QUIC_CID_VERSION_STATS;
//  struct lb_stats* quic_version =
//      stats.lookup(&quic_version_stats_key);
   struct lb_stats* quic_version = bpf_map_lookup_elem(&stats, &quic_version_stats_key);
  if (!quic_version) {
    return;
  }
  if (host_id > QUIC_CONNID_VERSION_V1_MAX_VAL) {
    quic_version->v2 += 1;
  } else {
    quic_version->v1 += 1;
  }
}

__attribute__((__always_inline__)) static inline void
increment_quic_cid_drop_no_real() {
  __u32 quic_drop_stats_key = MAX_VIPS + QUIC_CID_DROP_STATS;
//  struct lb_stats* quic_drop =
//      stats.lookup(&quic_drop_stats_key);
  struct lb_stats* quic_drop = bpf_map_lookup_elem(&stats, &quic_drop_stats_key);
  if (!quic_drop) {
    return;
  }
  quic_drop->v1 += 1;
}

__attribute__((__always_inline__)) static inline void
increment_quic_cid_drop_real_0() {
  __u32 quic_drop_stats_key = MAX_VIPS + QUIC_CID_DROP_STATS;
//  struct lb_stats* quic_drop =
//      stats.lookup(&quic_drop_stats_key);
  struct lb_stats* quic_drop = bpf_map_lookup_elem(&stats, &quic_drop_stats_key);
  if (!quic_drop) {
    return;
  }
  quic_drop->v2 += 1;
}

__attribute__((__always_inline__))
static inline int process_packet(struct CTXTYPE *ctx, void *data, __u64 off, void *data_end,
                                 bool is_ipv6, struct CTXTYPE *xdp) {
  log_debug("--------------");
  struct ctl_value *cval;
  struct real_definition *dst = NULL;
  struct packet_description pckt = {};
  struct vip_definition vip = {};
  struct vip_meta *vip_info;
  struct lb_stats *data_stats;
  __u64 iph_len;
  __u8 protocol;

  int action;
  __u32 vip_num;
  __u32 mac_addr_pos = 0;
  __u16 pkt_bytes;
  action = process_l3_headers(
    &pckt, &protocol, off, &pkt_bytes, data, data_end, is_ipv6);
  if (action >= 0) {
    return action;
  }
  protocol = pckt.flow.proto;

  if (protocol == IPPROTO_TCP) {
    if (!parse_tcp(data, data_end, is_ipv6, &pckt)) {
      //return RX_DROP;
      return XDP_DROP;
    }
  } else if (protocol == IPPROTO_UDP) {
    if (!parse_udp(data, data_end, is_ipv6, &pckt)) {
      //return RX_DROP;
      return XDP_DROP;
    }
  } else {
    // send to tcp/ip stack
    //return RX_OK;
    return XDP_PASS;  /* important! should pas here*/
  }

  struct vip_meta new_vip_info = {};

  vip.vip = pckt.flow.dst;

  vip.port = pckt.flow.port16[1];
  vip.proto = pckt.flow.proto;
  //vip_info = vip_map.lookup(&vip);
  /*data structures!*/

  /* @@@1 optimise point begin*/
#if USE_EBPF_MAP ==1
  vip_info = bpf_map_lookup_elem(&vip_map, &vip);
#else
  struct vip_meta vip_info_constant = {
    .flags = 1<<5, //F_LOCAL_VIP
    .vip_num = pckt.real_index
  };
  vip_info = &vip_info_constant;
#endif
  /* @@@1 optimise point end*/

  if (!vip_info) {
    log_debug("First VIP lookup failed for vip: 0x%x, port: %u, proto: %u", vip.vip, vip.port, vip.proto);
    //pcn_log(ctx, LOG_TRACE, "First VIP lookup failed for port: %u, proto: %u", bpf_ntohs(vip.port), vip.proto);
    // vip.port = 0;
    //vip_info = vip_map.lookup(&vip);
    vip_info = bpf_map_lookup_elem(&vip_map, &vip);
    if (!vip_info) {
      log_debug("Second VIP lookup failed for vip: 0x%x, port: %u, proto: %u", bpf_ntohs(vip.vip), bpf_ntohs(vip.port), bpf_ntohs(vip.proto));
      //pcn_log(ctx, LOG_TRACE, "VIP lookup failed for the default value. Dropping...");
      //return RX_DROP;
      return XDP_DROP;
    }

    if (!(vip_info->flags & F_HASH_DPORT_ONLY)) {
      // VIP, which doesnt care about dst port (all packets to this VIP w/ diff
      // dst port but from the same src port/ip must go to the same real
      //pcn_log(ctx, LOG_TRACE, "F_HASH_DPORT_ONLY not set. VIP doesn't care about dst port");
      pckt.flow.port16[1] = 0;
    }
  }

  if (data_end - data > MAX_PCKT_SIZE) {
    REPORT_PACKET_TOOBIG(xdp, data, data_end - data, false);
    //return RX_DROP;
    return XDP_DROP;
  }

  __u32 stats_key = MAX_VIPS + LRU_CNTRS;
  //data_stats = stats.lookup(&stats_key);

  /* @@@2 optimise point */
#if USE_EBPF_MAP ==1
  data_stats = bpf_map_lookup_elem(&stats, &stats_key);
#else
  struct lb_stats data_stats_constant = {
    .v1 = 1,
    .v2 = pckt.tos
  };
  data_stats = &data_stats_constant;
#endif

  if (!data_stats) {
    //return RX_DROP;
    log_debug("data_stats is null");
    return XDP_DROP;
  }

  // total packets
  data_stats->v1 += 1;
  log_debug("hit line %d", __LINE__);
  // if ((vip_info->flags & F_QUIC_VIP)) {
  //   //pcn_log(ctx, LOG_TRACE, "F_QUIC_VIP set for this VIP");
  //   __u32 quic_stats_key = MAX_VIPS + QUIC_ROUTE_STATS;
  //   //struct lb_stats* quic_stats = stats.lookup(&quic_stats_key);
  //   struct lb_stats* quic_stats = bpf_map_lookup_elem(&quic_stats, &quic_stats_key); /* !!! have bug here, expect ebpf map ptr*/
  //   if (!quic_stats) {
  //     //return RX_DROP;
  //     return XDP_DROP;
  //   }
  //   int real_index;
  //   real_index = parse_quic(data, data_end, is_ipv6, &pckt);
  //   if (real_index > 0) {
  //     increment_quic_cid_version_stats(real_index);
  //     __u32 key = real_index;
  //     //__u32 *real_pos = quic_mapping.lookup(&key);
  //     __u32 *real_pos = bpf_map_lookup_elem(&quic_mapping, &key);
  //     if (real_pos) {
  //       key = *real_pos;
  //       // TODO: quic_mapping is array, which never fails to lookup element,
  //       // resulting in default value 0 for real id
  //       if (key == 0) {
  //         increment_quic_cid_drop_real_0();
  //       }
  //       pckt.real_index = key;
  //       //dst = reals.lookup(&key);
  //       dst = bpf_map_lookup_elem(&reals, &key);
  //       if (!dst) {
  //         increment_quic_cid_drop_no_real();
  //         REPORT_QUIC_PACKET_DROP_NO_REAL(xdp, data, data_end - data, false);
  //         //return RX_DROP;
  //         return XDP_DROP;
  //       }
  //       quic_stats->v2 += 1;
  //     } else {
  //       // increment counter for the CH based routing
  //       quic_stats->v1 += 1;
  //     }
  //   } else {
  //     quic_stats->v1 += 1;
  //   }
  // }

  if (!dst) {
    log_debug("hit line %d", __LINE__);
    if ((vip_info->flags & F_HASH_NO_SRC_PORT)) {
      // service, where diff src port, but same ip must go to the same real,
      // e.g. gfs
      pckt.flow.port16[0] = 0;
    }
    __u32 cpu_num = bpf_get_smp_processor_id();
    //void *lru_map = lru_mapping.lookup(&cpu_num);

    /* @@@3 optimise point */
#if USE_EBPF_MAP ==1
    void *lru_map  = bpf_map_lookup_elem(&lru_mapping, &cpu_num);
#else
    void *lru_map = NULL;
#endif

    if (!lru_map) {
      log_debug("hit line %d", __LINE__);
      //pcn_log(ctx, LOG_TRACE, "LRU mapping lookup failed for CPU: %u", cpu_num);
      // lru_map = &fallback_cache;
      // I had to modify BCC to support this new kind of helper
      // that allows to return the pointer of the map
      //lru_map = (void *)fallback_cache.get_table_ptr(1);
      lru_map = (void*)&fallback_cache;
      __u32 lru_stats_key = MAX_VIPS + FALLBACK_LRU_CNTR;
      // struct lb_stats *lru_stats = stats.lookup(&lru_stats_key);
      struct lb_stats *lru_stats = bpf_map_lookup_elem(&stats, &lru_stats_key);
      if (!lru_stats) {
        log_debug("hit line %d", __LINE__);
        //return RX_DROP;
        return XDP_DROP;
      }
      // we weren't able to retrieve per cpu/core lru and falling back to
      // default one. this counter should never be anything except 0 in prod.
      // we are going to use it for monitoring.
      lru_stats->v1 += 1;
    }
    log_debug("hit line %d", __LINE__);
    if (!(vip_info->flags & F_LRU_BYPASS)) {
      //pcn_log(ctx, LOG_TRACE, "Packet is not SYN and F_LRU_BYPASS is not set");
      //pcn_log(ctx, LOG_TRACE, "Connection table lookup");
      //pcn_log(ctx, LOG_TRACE, "Current session info: IPsrc: %I, IPdst: %I", pckt.flow.src, pckt.flow.dst);
      //pcn_log(ctx, LOG_TRACE, "Port SRC: %u, Port DST: %u, Proto: %u", bpf_ntohs(pckt.flow.port16[0]), bpf_ntohs(pckt.flow.port16[1]), pckt.flow.proto);
      log_debug("hit line %d", __LINE__);
      struct real_pos_lru *dst_lru;
      __u64 cur_time;
      __u32 key;
      //dst_lru = bpf_map_lookup_elem_((uintptr_t)lru_map, &pckt.flow);

      /* @@@4 optimise point */
#if USE_EBPF_MAP ==1
      dst_lru = bpf_map_lookup_elem(lru_map, &pckt.flow);
#else
      struct real_pos_lru dst_lru_constant = {
        .pos = 0,
        .atime = pckt.real_index
      };
      dst_lru = &dst_lru_constant;
#endif

      if (!dst_lru) {
        //pcn_log(ctx, LOG_TRACE, "LRU map lookup failed for this flow");
        log_debug("hit line %d", __LINE__);
        goto dst_lookup;
      }
      
      key = dst_lru->pos;
      pckt.real_index = key;

      //pcn_log(ctx, LOG_TRACE, "Performing reals lookup for key: %u", key);
      //dst = reals.lookup(&key);
      /*important data structures lookup*/
      log_debug("hit line %d", __LINE__);

      /* @@@5 optimise point */
#if USE_EBPF_MAP ==1
      dst = bpf_map_lookup_elem(&reals, &key);
#else
      struct real_definition dst_constant = {
        .dst = 0,
        .flags = pckt.flags,
      };
      dst = &dst_constant;
#endif
    }

dst_lookup:;
    if (!dst) {
      //pcn_log(ctx, LOG_TRACE, "Destination not found, allocate new");
      if (pckt.flow.proto == IPPROTO_TCP) {
        log_debug("hit line %d", __LINE__);
        __u32 lru_stats_key = MAX_VIPS + LRU_MISS_CNTR;
        //struct lb_stats *lru_stats = stats.lookup(&lru_stats_key);
        struct lb_stats *lru_stats = bpf_map_lookup_elem(&stats, &lru_stats_key);
        if (!lru_stats) {
          //return RX_DROP;
          log_debug("hit line %d", __LINE__);
          return XDP_DROP;
        }
        if (pckt.flags & F_SYN_SET) {
          // miss because of new tcp session
          lru_stats->v1 += 1;
        } else {
          // miss of non-syn tcp packet. could be either because of LRU trashing
          // or because another katran is restarting and all the sessions
          // have been reshuffled
          log_debug("hit line %d", __LINE__);
          REPORT_TCP_NONSYN_LRUMISS(xdp, data, data_end - data, false);
          lru_stats->v2 += 1;
        }
      }
      if(!get_packet_dst(ctx, &dst, &pckt, vip_info, is_ipv6, lru_map)) {
        //return RX_DROP;
        return XDP_DROP;
      }
      // lru misses (either new connection or lru is full and starts to trash)
      data_stats->v2 += 1;
    }
  }

  //cval = ctl_array.lookup(&mac_addr_pos);
  /* @@@6 optimise point */
#if USE_EBPF_MAP ==1
  cval = bpf_map_lookup_elem(&ctl_array, &mac_addr_pos);
#else
  struct ctl_value cval_constant = {
    .mac = pckt.real_index,
  };
  cval = &cval_constant;
#endif
  log_debug("hit line %d", __LINE__);
  if (!cval) {
    log_debug("hit line %d", __LINE__);
    //return RX_DROP;
    return XDP_DROP;
  }

  vip_num = vip_info->vip_num;
  //data_stats = stats.lookup(&vip_num);

  /* @@@7 optimise point */
#if USE_EBPF_MAP ==1
  data_stats = bpf_map_lookup_elem(&stats, &vip_num);
#else
  struct lb_stats data_stats_constant2 = {
    .v1 = 0,
    .v2 = pckt.tos
  };
  data_stats = &data_stats_constant2;
#endif

  log_debug("hit line %d", __LINE__);
  if (!data_stats) {
    log_debug("hit line %d", __LINE__);
    //return RX_DROP;
    return XDP_DROP;
  }
  data_stats->v1 += 1;
  data_stats->v2 += pkt_bytes;

  // per real statistics
  //data_stats = reals_stats.lookup(&pckt.real_index);

  /* @@@8 optimise point */
#if USE_EBPF_MAP ==1
  data_stats = bpf_map_lookup_elem(&reals_stats, &pckt.real_index);
#else
  struct lb_stats data_stats_constant3 = {
    .v1 = 0,
    .v2 = pckt.tos
  };
  data_stats = &data_stats_constant3;
#endif

  log_debug("hit line %d", __LINE__);
  if (!data_stats) {
    log_debug("hit line %d", __LINE__);
    //return RX_DROP;
    return XDP_DROP;
  }
  data_stats->v1 += 1;
  data_stats->v2 += pkt_bytes;

  #ifdef LOCAL_DELIVERY_OPTIMIZATION
  if ((vip_info->flags & F_LOCAL_VIP) && (dst->flags & F_LOCAL_REAL)) {
    return RX_OK;
  }
#endif
    //pcn_log(ctx, LOG_TRACE, "Encapsulating IPv4 packet");
    //pcn_log(ctx, LOG_TRACE, "New real destination is: %I", dst->dst);
    if(!PCKT_ENCAP_V4(xdp, cval, &pckt, dst, pkt_bytes)) {
      //return RX_DROP;
      log_debug("hit line %d", __LINE__);
      return XDP_DROP;
    }
  log_debug("hit line %d", __LINE__);
  return XDP_TX;
}

struct pkt_metadata {
  u16 cube_id;        //__attribute__((deprecated)) // use CUBE_ID instead
  u16 in_port;        // The interface on which a packet was received.
  u32 packet_len;     //__attribute__((deprecated)) // Use ctx->len
  u32 traffic_class;  // The traffic class the packet belongs to

  // used to send data to controller
  u16 reason;
  u32 md[3];
} __attribute__((packed));


int __attribute__((always_inline)) handle_rx(struct CTXTYPE *ctx, struct pkt_metadata *md) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct eth_hdr *eth = data;
  __u32 eth_proto;
  __u32 nh_off;
  nh_off = sizeof(struct eth_hdr);

  if (data + nh_off > data_end) {
    // bogus packet, len less than minimum ethernet frame size
    //return RX_DROP;
    return XDP_DROP;
  }

  eth_proto = eth->eth_proto;

  if (eth_proto == BE_ETH_P_IP) {
    //pcn_log(ctx, LOG_TRACE, "Process IPv4 packet");
    return process_packet(ctx, data, nh_off, data_end, false, ctx);
  } else {
    // pass to tcp/ip stack
    //return RX_OK;
    return XDP_PASS;
  }
}

SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
  struct pkt_metadata meta = {
        .in_port = 0,
  };
  return handle_rx(ctx, &meta);
}