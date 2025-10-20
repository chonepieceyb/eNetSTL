#include "../config.h"
#include "../common.h"
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <netinet/tcp.h>
#include <bpf/bpf_endian.h>
#include "../bpf_skel/ebpf_nn_ids_base.skel.h"

struct bpf_progs_desc
{
    char name[256];
    enum bpf_prog_type type;
    int map_prog_idx;
    struct bpf_program *prog;
};

static struct bpf_progs_desc progs[] = {
    {"xdp_preprocessing", BPF_PROG_TYPE_XDP, 0, NULL},
    {"xdp_input_linear", BPF_PROG_TYPE_XDP, 1, NULL},
    {"xdp_input_relu", BPF_PROG_TYPE_XDP, 2, NULL},
    {"xdp_hidden_linear", BPF_PROG_TYPE_XDP, 3, NULL},
    {"xdp_hidden_relu", BPF_PROG_TYPE_XDP, 4, NULL},
    {"xdp_output_linear", BPF_PROG_TYPE_XDP, 5, NULL},
};

static int callback_before_load(void *skel)
{
	/* clear pinned maps */
	remove("/sys/fs/bpf/nn_parameters");
    	remove("/sys/fs/bpf/nn_idx");
	remove("/sys/fs/bpf/progs");
	return 0;
}

static int empty_callback_after_attach(void *skel)
{
	return 0;
}

static int callback_after_load(void *__skel)
{
	return 0;
}

int main(int argc, char **argv)
{
    BPF_XDP_SKEL_LOADER_WITH_CALLBACKS(ebpf_nn_ids_base, XDP_IF, xdp_main, 
		callback_before_load,
                callback_after_load,
		empty_callback_after_attach, 
			    XDP_MODE)
}