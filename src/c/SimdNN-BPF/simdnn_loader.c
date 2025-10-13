#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/resource.h>
#include <net/if.h>
#include <linux/if_link.h>
#include "../../bpf_kern/SimdNN-BPF/common.h"
#include "../../bpf_kern/SimdNN-BPF/mlp_params.bpf.h"
#include "../common.h"
#include "../bpf_skel/simdnn.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static int setup_model_map(struct bpf_map *model_map)
{
    __u32 key = 0;
    struct model model = {0};

    // Load model weights from mlp_params.bpf.h
    // Layer 1 weights (6 -> 32)
    for (int i = 0; i < 32; i++) {
        for (int j = 0; j < 6; j++) {
            model.fc1.weights[i][j] = layer_0_weight[i * 6 + j];
        }
        model.fc1.bias[i] = 0; // Bias not provided in params
    }

    // Layer 2 weights (32 -> 32)
    for (int i = 0; i < 32; i++) {
        for (int j = 0; j < 32; j++) {
            model.fc2.weights[i][j] = layer_1_weight[i * 32 + j];
        }
        model.fc2.bias[i] = 0; // Bias not provided in params
    }

    // Layer 3 weights (32 -> 2) - output layer
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 32; j++) {
            model.output.weights[i][j] = layer_2_weight[i * 32 + j];
        }
        model.output.bias[i] = 0; // Bias not provided in params
    }

    return bpf_map_update_elem(bpf_map__fd(model_map), &key, &model, BPF_ANY);
}

int main(int argc, char **argv)
{
    struct simdnn *skel;
    int err;
    const char *ifname = "eth0";

    if (argc > 1) {
        ifname = argv[1];
    }

    libbpf_set_print(libbpf_print_fn);

    // Increase rlimit
    struct rlimit rlim = {
        .rlim_cur = 512 * 1024 * 1024,
        .rlim_max = 512 * 1024 * 1024,
    };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK: %s\n", strerror(errno));
        return 1;
    }

    // Load and verify BPF application
    skel = simdnn__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Set up model map
    err = setup_model_map(skel->maps.model_map);
    if (err) {
        fprintf(stderr, "Failed to setup model map: %d\n", err);
        goto cleanup;
    }

    // Load & verify BPF programs
    err = simdnn__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
        goto cleanup;
    }

    // Attach XDP program
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Failed to get interface index: %s\n", strerror(errno));
        goto cleanup;
    }

    err = bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.xdp_simdnn_main),
                        XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    if (err) {
        fprintf(stderr, "Failed to attach XDP program: %d\n", err);
        goto cleanup;
    }

    printf("SimdNN-BPF XDP program loaded on interface %s\n", ifname);
    printf("Press Ctrl+C to exit...\n");

    // Set up signal handler
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Main loop - print statistics
    while (!exiting) {
        __u32 key = 0;
        __u64 stats = 0;

        // Read and print statistics
        err = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats_map), &key, &stats);
        if (!err) {
            printf("Packets processed: %llu\n", (unsigned long long)stats);
        }

        sleep(1);
    }

cleanup:
    // Detach XDP program
    if (ifindex) {
        bpf_xdp_detach(ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    }

    simdnn__destroy(skel);
    return err < 0 ? -err : 0;
}