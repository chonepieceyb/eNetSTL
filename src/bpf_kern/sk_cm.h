#ifndef _SK_CM_H
#define _SK_CM_H

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "common.h"

extern void bpf_countmin_add_avx2_pkt5(const struct pkt_5tuple *buf,
				       const u32 *seeds, u32 *values) __ksym;

#endif
