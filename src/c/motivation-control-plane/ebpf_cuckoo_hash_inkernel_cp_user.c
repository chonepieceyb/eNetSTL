#define _GNU_SOURCE
#include "../common.h"
#include "../bpf_skel/ebpf_cuckoo_hash_dp.skel.h"
#include "../bpf_skel/ebpf_cuckoo_hash_cp_iter.skel.h"
#include "../config.h"
#include "cuckoo_hash_operations.h"
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/sysinfo.h>
#include <arpa/inet.h>

#define PIN_PATH "/sys/fs/bpf/cuckoo_hash_map"
#define MAX_PAIRS_ENTRIES 16

volatile sig_atomic_t running = 1;

// Signal handler for graceful shutdown
static void handle_sigint(int sig) {
    printf("Received SIGINT, shutting down gracefully...\n");
    running = 0;
}

// Fix type definitions for BPF skeleton
typedef __u32 u32;
typedef __u16 u16;
typedef __u8 u8;

// Define structures from eBPF program
struct update_record {
        __u32 key;
        int succeeded;
};

struct cuckoo_hash_pair {
        cuckoo_hash_key_t key;
        cuckoo_hash_value_t value;
        int updated;
};

struct dummy_struct {
        struct cuckoo_hash cuckoo_hash;
        struct __cuckoo_hash_key padd1[65536];
        struct __cuckoo_hash_bucket padd2[65536];
};

// Function to get pinned map's file descriptor
static int get_pinned_map_fd() {
    int fd = bpf_obj_get(PIN_PATH);
    if (fd < 0) {
        printf("Failed to get pinned map: %s\n", strerror(errno));
        return -1;
    }
    return fd;
}

// Generate fixed keys for CUCKOO_HASH_ENTRIES entries - keys remain constant
static void generate_fixed_key(cuckoo_hash_key_t *key, int index) {
    key->pkt.src_ip = htonl(0x0A000001 + (index & 0xFF));        // 10.0.0.1 to 10.0.0.255
    key->pkt.dst_ip = htonl(0x0A000100 + ((index >> 8) & 0xFF));  // 10.0.1.0 to 10.0.1.255
    key->pkt.src_port = htons(1024 + (index % 1000));            // Ports 1024-2023
    key->pkt.dst_port = htons(8000 + (index % 1000));             // Ports 8000-9000
    key->pkt.proto = 1 + (index % 3);                      // TCP=1, UDP=2, ICMP=3
    // Pad bytes remain 0
}

// Function to pin process to specific CPU core
static int pin_to_cpu_core(int core_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);

    pid_t current_pid = getpid();
    if (sched_setaffinity(current_pid, sizeof(cpu_set_t), &cpuset) < 0) {
        printf("Failed to pin process to CPU core %d: %s\n", core_id, strerror(errno));
        return -1;
    }

    printf("Successfully pinned process to CPU core %d\n", core_id);
    return 0;
}

// Function to clear previously pinned map
static int clear_pinned_map(void) {
    // Check if pinned map exists and remove it
    int fd = bpf_obj_get(PIN_PATH);
    if (fd >= 0) {
        printf("Found existing pinned map at %s, removing...\n", PIN_PATH);
        close(fd);

        // Try to unlink the pinned map
        if (unlink(PIN_PATH) == 0) {
            printf("Successfully removed existing pinned map\n");
        } else {
            printf("Warning: Failed to unlink pinned map: %s\n", strerror(errno));
            // Continue even if unlink fails
        }
    } else if (errno == ENOENT) {
        printf("No existing pinned map found at %s\n", PIN_PATH);
    } else {
        printf("Warning: Error checking pinned map: %s\n", strerror(errno));
    }

    return 0;
}

// Function to load BPF skeleton and pin map without attaching XDP
static int load_bpf_and_pin_map(void) {
    struct ebpf_cuckoo_hash_dp *skel = NULL;
    int res = 0;

    printf("Loading BPF skeleton for map initialization...\n");

    // Clear any previously pinned map first
    clear_pinned_map();

    // Open the BPF skeleton
    skel = ebpf_cuckoo_hash_dp__open();
    if (skel == NULL) {
        printf("Failed to open BPF skeleton\n");
        return -1;
    }

    // Load the BPF program
    res = ebpf_cuckoo_hash_dp__load(skel);
    if (res != 0) {
        printf("Failed to load BPF program: %d\n", res);
        goto cleanup;
    }

    // Initialize cuckoo_hash_map with zeros
    int zero = 0;
    struct dummy_struct init_struct = {0};
    struct cuckoo_hash *h = (struct cuckoo_hash*)(&init_struct);

    for (int i = 1; i < CUCKOO_HASH_KEY_SLOTS; i++) {
        __cuckoo_hash_enqueue_slot_back(h, i);
    }
    h->initialized = 1;

    // Initialize the hash table map
    res = bpf_map_update_elem(bpf_map__fd(skel->maps.cuckoo_hash_map), &zero, &init_struct, 0);
    if (res != 0) {
        printf("Failed to initialize cuckoo_hash_map: %d\n", res);
        goto cleanup;
    }

    printf("BPF skeleton loaded, maps initialized and pinned successfully\n");

cleanup:
    ebpf_cuckoo_hash_dp__destroy(skel);
    return res;
}

// In-kernel control plane update loop using BPF iter
static void inkernel_update_loop(int insertion_frequency, int cpu_core) {
    struct ebpf_cuckoo_hash_cp_iter *iter_skel = NULL;
    struct bpf_link *link = NULL;
    union bpf_iter_link_info linfo = {0};
    LIBBPF_OPTS(bpf_iter_attach_opts, opts);
    int iter_fd, ret, map_fd;
    char buf[4096];
    ssize_t len;

    printf("Starting in-kernel control plane update loop...\n");

    // Pin to specific CPU core if requested
    if (cpu_core >= 0) {
        if (pin_to_cpu_core(cpu_core) != 0) {
            printf("Warning: Failed to pin to CPU core %d, continuing without CPU affinity\n", cpu_core);
        }
    }

    // Open and load iter skeleton
    iter_skel = ebpf_cuckoo_hash_cp_iter__open();
    if (!iter_skel) {
        printf("Failed to open iter skeleton\n");
        return;
    }

    // Load the BPF program
    ret = ebpf_cuckoo_hash_cp_iter__load(iter_skel);
    if (ret != 0) {
        printf("Failed to load iter skeleton: %d\n", ret);
        goto cleanup;
    }

    // Get map fd for the pairs map
    map_fd = bpf_map__fd(iter_skel->maps.cuckoo_hash_pairs_map);
    if (map_fd < 0) {
        printf("Failed to get cuckoo_hash_pairs_map fd: %d\n", map_fd);
        goto cleanup;
    }

    printf("In-kernel control plane ready (PID: %d)\n", getpid());
    printf("Insertion frequency: %d microseconds\n", insertion_frequency);
    if (cpu_core >= 0) {
        printf("Pinned to CPU core: %d\n", cpu_core);
    }
    printf("Mode: In-kernel control plane using BPF iter\n");
    printf("Press Ctrl+C to stop...\n");

    int operations = 0;
    int insertions = 0;
    int current_key_index = 0;
    int update_count = 0;

    // Pre-generate all fixed keys once
    cuckoo_hash_key_t fixed_keys[CUCKOO_HASH_ENTRIES];
    for (int i = 0; i < CUCKOO_HASH_ENTRIES; i++) {
        generate_fixed_key(&fixed_keys[i], i);
    }

    // Attach iter program once (as per TODO comment)
    linfo.map.map_fd = map_fd;
    opts.link_info = &linfo;
    opts.link_info_len = sizeof(linfo);

    link = bpf_program__attach_iter(iter_skel->progs.cuckoo_hash_inkernel_cp, &opts);
    if (!link) {
        printf("Failed to attach iter program\n");
        goto cleanup;
    }

    while (running) {
        // Add one key-value pair to the map
        struct cuckoo_hash_pair pair = {0};
        int zero = 0; // Always use key 0 as per TODO comment

        // Create test key using current key index
        // Always use key 0 in bpf_map_update_elem as per TODO comment
        pair.key = fixed_keys[current_key_index];
        pair.value = 100 + (update_count % 900); // Values from 100-999
        pair.updated = 0; // Mark as not updated yet

        // Add to pairs map using key 0 (fixed location)
        ret = bpf_map_update_elem(map_fd, &zero, &pair, BPF_ANY);
        if (ret != 0) {
            printf("Failed to update cuckoo_hash_pairs_map[0]: %d\n", ret);
            continue;
        }

        // Create iter fd multiple times (as per TODO comment - attach once, create iter multiple times)
        iter_fd = bpf_iter_create(bpf_link__fd(link));
        if (iter_fd < 0) {
            printf("Failed to create iter fd: %d\n", iter_fd);
            continue;
        }

        // Read results from iter
        memset(buf, 0, sizeof(buf));
        len = read(iter_fd, buf, sizeof(buf) - 1);
        if (len < 0) {
            printf("Failed to read from iter: %s\n", strerror(errno));
            close(iter_fd);
            bpf_link__destroy(link);
            continue;
        }

        // Parse results and check if our update succeeded
        struct update_record *record = (struct update_record *)buf;
        int num_records = len / sizeof(struct update_record);
        int success_found = 0;

        for (int i = 0; i < num_records; i++) {
            // Since we're always using key 0, we check for key 0 in the record
            if (record[i].key == 0 && record[i].succeeded) {
                success_found = 1;
                insertions++;
                break;
            }
        }

        operations++;

        // Print statistics periodically
        if (operations % 10 == 0) {
            printf("Operations: %d, Insertions: %d, Success rate: %.2f%%, Key: %d/%d, Value: %d, Updates: %d\n",
                   operations, insertions, (float)insertions/operations*100,
                   current_key_index, CUCKOO_HASH_ENTRIES, 100 + (update_count % 900), update_count);
        }

        close(iter_fd);

        // Move to next key and increment update counter
        current_key_index = (current_key_index + 1) % CUCKOO_HASH_ENTRIES;
        update_count++;

        // Control insertion frequency
        usleep(insertion_frequency);
    }

cleanup:
    if (link)
        bpf_link__destroy(link);
    if (iter_skel)
        ebpf_cuckoo_hash_cp_iter__destroy(iter_skel);

    printf("In-kernel control plane update loop stopped. Total operations: %d, Total insertions: %d, Total updates: %d\n",
           operations, insertions, update_count);
}

static void print_usage(const char *prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  -f, --frequency FREQ    Insertion frequency in microseconds (default: 1000000)\n");
    printf("  -c, --cpu-core CORE     Pin to specific CPU core (default: -1, no pinning)\n");
    printf("  -h, --help             Show this help message\n");
    printf("\nNotes:\n");
    printf("  This program uses in-kernel control plane with BPF iter for updates.\n");
    printf("  Map will be pinned to %s\n", PIN_PATH);
    printf("  Press Ctrl+C to stop the update loop.\n");
    printf("  Uses optimized approach: attach once, create iter multiple times.\n");
    printf("  Always updates map key 0 with current key-value pair.\n");
    printf("\nCPU Core Pinning:\n");
    printf("  Use -c option to pin to a specific CPU core for better performance.\n");
    printf("  Core IDs start from 0. Use -1 for no CPU affinity (default).\n");
}

int main(int argc, char *argv[])
{
    int insertion_frequency = 1000000; // Default: 1 second
    int cpu_core = -1; // Default: no CPU core pinning

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if ((strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--frequency") == 0) && i + 1 < argc) {
            insertion_frequency = atoi(argv[++i]);
            if (insertion_frequency < 10 || insertion_frequency > 10000000) {
                printf("Invalid frequency. Using default (1000000 microseconds).\n");
                printf("Frequency must be between 10 and 10000000 microseconds.\n");
                insertion_frequency = 1000000;
            }
        } else if ((strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--cpu-core") == 0) && i + 1 < argc) {
            cpu_core = atoi(argv[++i]);
            // Validate CPU core ID
            int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
            if (cpu_core < -1 || cpu_core >= num_cores) {
                printf("Invalid CPU core %d. System has %d cores. Using default (no pinning).\n", cpu_core, num_cores);
                cpu_core = -1;
            } else if (cpu_core >= 0) {
                printf("Will pin to CPU core %d\n", cpu_core);
            }
        } else {
            printf("Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    // Load BPF skeleton and pin map without attaching XDP program
    int bpf_load_result = load_bpf_and_pin_map();
    if (bpf_load_result != 0) {
        printf("Failed to load BPF skeleton and pin map\n");
        return 1;
    }

    // Set up signal handler for Ctrl+C
    struct sigaction sa_int;
    sa_int.sa_handler = handle_sigint;
    sigemptyset(&sa_int.sa_mask);
    sa_int.sa_flags = 0;
    sigaction(SIGINT, &sa_int, NULL);

    printf("Starting in-kernel control plane cuckoo hash update loop...\n");
    printf("Insertion frequency: %d microseconds\n", insertion_frequency);
    if (cpu_core >= 0) {
        printf("CPU core pinning: %d\n", cpu_core);
    } else {
        printf("CPU core pinning: disabled\n");
    }

    // Run the in-kernel control plane update loop
    inkernel_update_loop(insertion_frequency, cpu_core);

    printf("Program exited gracefully.\n");
    return 0;
}