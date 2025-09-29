#define _GNU_SOURCE
#include "../common.h"
#include "../bpf_skel/ebpf_cuckoo_hash_dp.skel.h"
#include "../config.h"
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>

#define PIN_PATH "/sys/fs/bpf/cuckoo_hash_map"






static void print_usage(const char *prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  -h, --help             Show this help message\n");
    printf("\nDescription:\n");
    printf("  This program loads the eBPF cuckoo hash datapath program and pins the map.\n");
    printf("  Use ebpf_cuckoo_hash_update_user to run the update loop.\n");
}


// Function to load BPF program and return result
static int load_bpf_program(void) {
    BPF_XDP_SKEL_LOADER(ebpf_cuckoo_hash_dp, XDP_IF, xdp_main, XDP_MODE);
}

int main(int argc, char *argv[])
{
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            printf("Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    printf("Loading eBPF cuckoo hash datapath program...\n");

    // Load BPF program and pin map
    int bpf_load_result = load_bpf_program();

    if (bpf_load_result != 0) {
        printf("Failed to load BPF program\n");
        return 1;
    }

    printf("✅ BPF program loaded and map pinned successfully.\n");
    printf("📍 Map pinned to: %s\n", PIN_PATH);
    printf("🚀 Use ebpf_cuckoo_hash_update_user to run the update loop.\n");

    return 0;
}