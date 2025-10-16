#include "../common.h"
#include "../config.h"
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <netinet/tcp.h>
#include <bpf/bpf_endian.h>
#include "arena_skiplist_common.h"
#include "../bpf_skel/ebpf_arena_skiplist_lookup_16.skel.h"

static int callback_after_load(void *__skel)
{
    struct ebpf_arena_skiplist_lookup_16 *skel = (struct ebpf_arena_skiplist_lookup_16 *)__skel;
    //initialize the skip list
    LIBBPF_OPTS(bpf_test_run_opts, opts);
    struct bpf_program *prog_init;
    int ret;

	//Set program flags for testing
	prog_init = skel->progs.arena_skiplist_init;

	/* RUN INIT */
	ret = bpf_prog_test_run_opts(bpf_program__fd(prog_init), &opts);
    if (ret != 0 || opts.retval != 0) {
        fprintf(stderr, "Failed to run arena_skiplist_init: ret=%d, retval=%d\n", ret, opts.retval);
        return -1;
    }
	return 0;
}

int main(int argc, char **argv)
{
    BPF_XDP_SKEL_LOADER_WITH_AFTER_LOAD(ebpf_arena_skiplist_lookup_16, XDP_IF, xdp_main,
                callback_after_load,
			    XDP_MODE)
    return 0;
}