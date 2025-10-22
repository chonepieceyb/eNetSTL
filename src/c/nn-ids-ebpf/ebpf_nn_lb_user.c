#include "../config.h"
#include "../common.h"
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <netinet/tcp.h>
#include <bpf/bpf_endian.h>
#include "../bpf_skel/ebpf_nn_lb.skel.h"

/*for lb use lesser hidden neutrons to 12 */

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
    {"xdp_hidden_linear2", BPF_PROG_TYPE_XDP, 5, NULL},  //add hidden layer 2
    {"xdp_hidden_relu2", BPF_PROG_TYPE_XDP, 6, NULL},
    {"xdp_output_linear", BPF_PROG_TYPE_XDP, 7, NULL},
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
	struct ebpf_nn_lb *skel = (struct ebpf_nn_lb *)__skel;
	//initialize the skip list
        
	int map_progs_fd = bpf_object__find_map_fd_by_name(skel->obj, "progs");
	int prog_count = sizeof(progs) / sizeof(progs[0]);
        int err;
	for (int i = 0; i < prog_count; i++)
	{
		progs[i].prog = bpf_object__find_program_by_name(skel->obj, progs[i].name);
		if (!progs[i].prog)
		{
		fprintf(stderr, "Error: bpf_object__find_program_by_name failed\n");
		return 1;
		}
		bpf_program__set_type(progs[i].prog, progs[i].type);
	}

	for (int i = 0; i < prog_count; i++)
	{
		int prog_fd = bpf_program__fd(progs[i].prog);
		if (prog_fd < 0)
		{
			fprintf(stderr, "Error: Couldn't get file descriptor for program %s\n", progs[i].name);
			return 1;
		}

		unsigned int map_prog_idx = progs[i].map_prog_idx;
		if (map_prog_idx < 0)
		{
			fprintf(stderr, "Error: Cannot get prog fd for bpf program %s\n", progs[i].name);
			return 1;
		}
		// 给 progs map 的 map_prog_idx 插入 prog_fd
		err = bpf_map_update_elem(map_progs_fd, &map_prog_idx, &prog_fd, 0);
		if (err)
		{
			fprintf(stderr, "Error: bpf_map_update_elem failed for prog array map\n");
			return 1;
		}
		fprintf(stdout, "Successfully inserted prog fd %d for program %s at index %u in progs map\n",
			prog_fd, progs[i].name, map_prog_idx);
	}

	//  update nn index
	int32_t nn_idx = 0;
	int32_t nn_idx_value = 1;

	err = bpf_map__update_elem(skel->maps.nn_idx, &nn_idx, sizeof(int32_t), &nn_idx_value, sizeof(int32_t), BPF_ANY);
	if (err)
	{
		fprintf(stderr, "Error: updating nn index\n");
		return 1;
	}
	fprintf(stdout, "Successfully updated nn index to %d\n", nn_idx_value);
	return 0;
}

int main(int argc, char **argv)
{
    BPF_XDP_SKEL_LOADER_WITH_CALLBACKS(ebpf_nn_lb, XDP_IF, xdp_main, 
		callback_before_load,
                callback_after_load,
		empty_callback_after_attach, 
			    XDP_MODE)
}