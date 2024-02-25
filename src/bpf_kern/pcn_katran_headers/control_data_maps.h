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

#ifndef __CONTROL_DATA_MAPS_H
#define __CONTROL_DATA_MAPS_H

#include "../common.h"
#include "balancer_consts.h"
#include "balancer_structs.h"

// control array. contains metadata such as default router mac
// and/or interfaces ifindexes
// indexes:
// 0 - default's mac
//BPF_ARRAY(ctl_array, struct ctl_value, CTL_MAP_SIZE);

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value,  struct ctl_value);  
	__uint(max_entries, CTL_MAP_SIZE);   
} ctl_array SEC(".maps");

#ifdef INLINE_DECAP_GENERIC
//BPF_HASH(decap_dst, struct address, __u32, MAX_VIPS);
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct address);
	__type(value,  __u32);  
	__uint(max_entries, MAX_VIPS);   
} decap_dst SEC(".maps");
#endif

#ifdef GUE_ENCAP
// map which src ip address for outer ip packet while using GUE encap
// NOTE: This is not a stable API. This is to be reworked when static
// variables will be available in mainline kernels
//BPF_ARRAY(pckt_srcs, struct real_definition, 2);

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value,  struct real_definition);  
	__uint(max_entries, 2);   
} pckt_srcs SEC(".maps");
#endif


#endif // of __CONTROL_DATA_MAPS_H