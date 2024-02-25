/*
 * Copyright 2018 The Polycube Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*modified by chonepeieceyb*/

#ifndef FDB_TIMEOUT
#define FDB_TIMEOUT 300
#endif

#include "common.h"
char _license[] SEC("license") = "GPL";
#define REASON_FLOODING 0x01

#define USE_EBPF_MAP 1

struct pkt_metadata {
  u16 cube_id;        //__attribute__((deprecated)) // use CUBE_ID instead
  u16 in_port;        // The interface on which a packet was received.
  u32 packet_len;     //__attribute__((deprecated)) // Use ctx->len
  u32 traffic_class;  // The traffic class the packet belongs to

  // used to send data to controller
  u16 reason;
  u32 md[3];
} __attribute__((packed));

struct fwd_entry {
  u32 timestamp;
  u32 port;
} __attribute__((packed, aligned(8)));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __be64);
	__type(value,  struct fwd_entry);  
	__uint(max_entries, 1024);
} fwdtable SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value,  uint32_t);  
	__uint(max_entries, 1);
} timestamp SEC(".maps");

// BPF_TABLE("hash", __be64, struct fwd_entry, fwdtable, 1024);
// BPF_TABLE("array", int, uint32_t, timestamp, 1);


struct eth_hdr {
  __be64 dst : 48;
  __be64 src : 48;
  __be16 proto;
} __attribute__((packed));

static __always_inline u32 time_get_sec() {
  int key = 0;
  //u32 *ts = timestamp.lookup(&key);
  /*data structure 1*/
  u32 *ts = bpf_map_lookup_elem(&timestamp, &key);
  if (ts)
    return *ts;

  return 0;
}

#define CTXTYPE xdp_md


int pcn_pkt_redirect(struct CTXTYPE *pkt, struct pkt_metadata *md, u32 out_port) {
        /*directly drop it*/
        return 0;
};

static __always_inline int handle_rx(struct CTXTYPE *ctx,
                                     struct pkt_metadata *md) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct eth_hdr *eth = data;

  if (data + sizeof(*eth) > data_end)
    return XDP_DROP;

  u32 in_ifc = md->in_port;

//   pcn_log(ctx, LOG_TRACE, "Received a new packet from port %d", in_ifc);
//   pcn_log(ctx, LOG_TRACE, "mac src:%M dst:%M", eth->src, eth->dst);

  // LEARNING PHASE
  __be64 src_key = eth->src;
  u32 now = time_get_sec();

  //struct fwd_entry *entry = fwdtable.lookup(&src_key);
  /*Data structure2 */
  //struct fwd_entry *entry = fwdtable.lookup(&src_key);

#if USE_EBPF_MAP == 1
  struct fwd_entry *entry = bpf_map_lookup_elem(&fwdtable, &src_key);
#else
  struct fwd_entry entry_without_search = {
    .timestamp = 0x11112222,
    .port = eth->src,
  };
  struct fwd_entry *entry = &entry_without_search;
#endif

  if (!entry) {
    struct fwd_entry e;  // used to update the entry in the fdb

    e.timestamp = now;
    e.port = in_ifc;

    //fwdtable.update(&src_key, &e);
    /*Data structure3 */
    bpf_map_update_elem(&fwdtable, &src_key, &e, 0);
    //pcn_log(ctx, LOG_TRACE, "MAC: %M learned", src_key);
  } else {
    entry->port = in_ifc;
    entry->timestamp = now;
  }

  // FORWARDING PHASE: select interface(s) to send the packet
  __be64 dst_mac = eth->dst;
  // lookup in forwarding table fwdtable
  //entry = fwdtable.lookup(&dst_mac);
  /*Data structure4 */

#if USE_EBPF_MAP == 1
  entry = bpf_map_lookup_elem(&fwdtable, &dst_mac);
#else
  struct fwd_entry entry_without_search = {
    .timestamp = 0x11112222,
    .port = eth->src,
  };
  entry = NULL;
#endif
  if (!entry) {
    log_debug("dst_mac not found in fwdtable.\n");
   // pcn_log(ctx, LOG_DEBUG, "Entry not found for dst-mac: %M", dst_mac);
    goto DO_FLOODING;
  }

  u64 timestamp = entry->timestamp;

  // Check if the entry is still valid (not too old)
  if ((now - timestamp) > FDB_TIMEOUT) {
    //pcn_log(ctx, LOG_TRACE, "Entry is too old. FLOODING");
    //fwdtable.delete(&dst_mac);
    // bpf_map_delete_elem(&fwdtable, &dst_mac);
    goto DO_FLOODING;
  }
  //pcn_log(ctx, LOG_TRACE, "Entry is valid. FORWARDING");

FORWARD:;
  u32 dst_interface = entry->port;  // workaround for verifier

  // HIT in forwarding table
  // redirect packet to dst_interface

  /* do not send packet back on the ingress interface */
  if (dst_interface == in_ifc) {
//     pcn_log(
//         ctx, LOG_TRACE,
//         "Destination interface is equals to the input interface. DROP packet");
//     return RX_DROP;
        return XDP_DROP;
  }

//   pcn_log(ctx, LOG_DEBUG, "Redirect packet to port %d", dst_interface);
  return pcn_pkt_redirect(ctx, md, dst_interface);

DO_FLOODING:
//   pcn_log(ctx, LOG_DEBUG, "Flooding required: sending packet to controller");
//   pcn_pkt_controller(ctx, md, REASON_FLOODING);
//   return RX_DROP;
  return XDP_DROP;
}

SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
        /*fix pkt_metadata*/
        struct pkt_metadata meta = {
                .in_port = 0,
        };
        return handle_rx(ctx, &meta);
}