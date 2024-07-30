#include "vmlinux.h"
#include "bpf_helpers.h"
#include "common.h"

char _license[] SEC("license") = "GPL";

#define __TARGET_ARCH_x86
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct pkt_count);
	__uint(max_entries, 40);
	__uint(pinning, 1);
} count_map SEC(".maps");