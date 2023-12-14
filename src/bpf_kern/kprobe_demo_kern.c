
#include "common.h"

#define __TARGET_ARCH_x86
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, int);  
	__uint(max_entries, 1);
} fd_array SEC(".maps");

SEC("kprobe/__sys_connect")
int BPF_KPROBE(kprobe_demo, int dfd) 
{
	//write the fd of open syscall to BPF ARRAY
	int key = 0;
	int res;
	res = bpf_map_update_elem(&fd_array, &key, &dfd, 0);
	log_debug("kprobe helloworld, dfd %d, update to map %d\n", dfd, res);
	return 0;
}