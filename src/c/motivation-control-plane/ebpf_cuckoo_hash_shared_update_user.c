#define _GNU_SOURCE
#include "../common.h"
#include "../bpf_skel/ebpf_cuckoo_hash_dp.skel.h"
#include "../config.h"
#include "cuckoo_hash_operations.h"
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/sysinfo.h>

#define PIN_PATH "/sys/fs/bpf/cuckoo_hash_map"

// Helper function to round up to page size
static size_t roundup_page(size_t sz) {
    long page_size = sysconf(_SC_PAGE_SIZE);
    return (sz + page_size - 1) / page_size * page_size;
}

// Helper function to get BPF map info for debugging
static void debug_map_info(int map_fd) {
    struct bpf_map_info map_info = {0};
    __u32 map_info_len = sizeof(map_info);
    int err;

    printf("DEBUG: Getting map info for fd=%d\n", map_fd);

    err = bpf_map_get_info_by_fd(map_fd, &map_info, &map_info_len);
    if (err == 0) {
        printf("DEBUG: Map info:\n");
        printf("  type: %d\n", map_info.type);
        printf("  key_size: %u\n", map_info.key_size);
        printf("  value_size: %u\n", map_info.value_size);
        printf("  max_entries: %u\n", map_info.max_entries);
        printf("  map_flags: 0x%x\n", map_info.map_flags);
        printf("  name: %s\n", map_info.name);
        printf("  ifindex: %u\n", map_info.ifindex);
        printf("  btf_vmlinux_value_type_id: %u\n", map_info.btf_vmlinux_value_type_id);
        printf("  netns_dev: %llu\n", map_info.netns_dev);
        printf("  netns_ino: %llu\n", map_info.netns_ino);
    } else {
        printf("DEBUG: Failed to get map info: %s\n", strerror(errno));
    }
}

volatile sig_atomic_t running = 1;

// Signal handler for graceful shutdown
static void handle_sigint(int sig) {
    printf("Received SIGINT, shutting down gracefully...\n");
    running = 0;
}

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
    key->pkt.src_ip = 0x0A000001 + (index & 0xFF);        // 10.0.0.1 to 10.0.0.255
    key->pkt.dst_ip = 0x0A000100 + ((index >> 8) & 0xFF);  // 10.0.1.0 to 10.0.1.255
    key->pkt.src_port = 1024 + (index % 1000);            // Ports 1024-2023
    key->pkt.dst_port = 8000 + (index % 1000);             // Ports 8000-9000
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

    printf("Loading BPF skeleton...\n");

    // Clear any previously pinned map first
    clear_pinned_map();

    // Open the BPF skeleton
    skel = ebpf_cuckoo_hash_dp__open();
    if (skel == NULL) {
        printf("Failed to open BPF skeleton\n");
        return -1;
    }
    bpf_map__set_map_flags(skel->maps.cuckoo_hash_map, BPF_F_MMAPABLE);
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

    // Initialize the hash table map using syscall (map needs to be created first)
    res = bpf_map_update_elem(bpf_map__fd(skel->maps.cuckoo_hash_map), &zero, h, 0);
    if (res != 0) {
        printf("Failed to initialize cuckoo_hash_map: %d\n", res);
        goto cleanup;
    }

    printf("BPF skeleton loaded, maps initialized and pinned successfully\n");

cleanup:
    ebpf_cuckoo_hash_dp__destroy(skel);
    return res;
}


// Simple update loop function (non-daemon) - updates fixed keys with varying values
static void update_loop(int insertion_frequency, int cpu_core, int verbose) {
    struct __cuckoo_hash_bfs_queue bfs_queue = {0};
    struct dummy_struct *hash_tab = NULL;
    void *map_mmaped = NULL;
    struct dummy_struct local_hash_tab = {0};
    int use_shared_memory = 0;

    // Get map file descriptor
    int map_fd = get_pinned_map_fd();
    if (map_fd < 0) {
        printf("Failed to get map file descriptor. Make sure the BPF program is loaded and map is pinned.\n");
        return;
    }

    // Try to map the BPF map into shared memory
    size_t map_sz = roundup_page(sizeof(struct dummy_struct));
    size_t struct_size = sizeof(struct dummy_struct);
    long page_size = sysconf(_SC_PAGE_SIZE);

    printf("DEBUG: Attempting to mmap BPF map:\n");
    printf("  map_fd: %d\n", map_fd);
    printf("  struct_size: %zu\n", struct_size);
    printf("  map_sz (rounded): %zu\n", map_sz);
    printf("  page_size: %ld\n", page_size);

    // Debug map info
    debug_map_info(map_fd);

    printf("DEBUG: Calling mmap(NULL, %zu, PROT_READ|PROT_WRITE, MAP_SHARED, %d, 0)\n",
           map_sz, map_fd);

    map_mmaped = mmap(NULL, map_sz, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
    if (map_mmaped == MAP_FAILED) {
        printf("DEBUG: mmap failed with error: %s (errno=%d)\n", strerror(errno), errno);
        printf("Failed to mmap cuckoo_hash_map: %s, falling back to syscall method\n", strerror(errno));

        // Try different mmap parameters to diagnose the issue
        printf("DEBUG: Trying mmap with read-only access...\n");
        void *ro_mmap = mmap(NULL, map_sz, PROT_READ, MAP_SHARED, map_fd, 0);
        if (ro_mmap == MAP_FAILED) {
            printf("DEBUG: Read-only mmap also failed: %s (errno=%d)\n", strerror(errno), errno);
        } else {
            printf("DEBUG: Read-only mmap succeeded at %p\n", ro_mmap);
            munmap(ro_mmap, map_sz);
        }

        hash_tab = &local_hash_tab;
        use_shared_memory = 0;
    } else {
        printf("DEBUG: mmap succeeded at address %p\n", map_mmaped);
        printf("Successfully mapped BPF map into shared memory\n");
        hash_tab = (struct dummy_struct*)map_mmaped;
        use_shared_memory = 1;
    }

    // Pin to specific CPU core if requested
    if (cpu_core >= 0) {
        if (pin_to_cpu_core(cpu_core) != 0) {
            printf("Warning: Failed to pin to CPU core %d, continuing without CPU affinity\n", cpu_core);
        }
    }

    printf("Update loop started (PID: %d)\n", getpid());
    printf("Insertion frequency: %d microseconds\n", insertion_frequency);
    if (cpu_core >= 0) {
        printf("Pinned to CPU core: %d\n", cpu_core);
    }
    printf("Mode: Fixed keys with incrementing values (%s)\n",
           use_shared_memory ? "using shared memory for updates" : "using syscall method");
    printf("Press Ctrl+C to stop...\n");

    int operations = 0;
    int insertions = 0;
    int current_key_index = 0;
    int update_count = 0; // Track number of updates to increment values

    // Pre-generate all fixed keys once
    cuckoo_hash_key_t fixed_keys[CUCKOO_HASH_ENTRIES];
    for (int i = 0; i < CUCKOO_HASH_ENTRIES; i++) {
        generate_fixed_key(&fixed_keys[i], i);
    }

    while (running) {
        if (use_shared_memory) {
            // Use shared memory directly - no need for bpf_map_lookup_elem
            // hash_tab already points to the shared memory region

            // Set up parameters with shared memory hash table
            struct cuckoo_hash_parameters params = {
                .hash_table = (struct cuckoo_hash*)&hash_tab->cuckoo_hash,
                .bfs_queue = &bfs_queue,
            };

            // Update fixed key with incrementing value
            cuckoo_hash_key_t key_data = fixed_keys[current_key_index];
            cuckoo_hash_value_t value = 100 + (update_count % 900); // Values from 100-999

            int ret = cuckoo_hash_update_elem(&params, &key_data, &value);
            if (ret == 0) {
                insertions++;
                operations++;
            } else if (ret == -ENOSPC) {
                printf("Hash table is full (ENOSPC)\n");
            } else if (ret == -EINVAL) {
                printf("Invalid parameters (EINVAL)\n");
            } else {
                printf("Failed to update key-value pair: %d\n", ret);
            }

            // No need for bpf_map_update_elem - changes are automatically reflected
            // in shared memory
        } else {
            // Fall back to syscall method
            int key = 0;
            int ret = bpf_map_lookup_elem(map_fd, &key, &local_hash_tab);
            if (ret != 0) {
                printf("Failed to lookup cuckoo hash map, ret %d: %s\n", ret, strerror(errno));
                usleep(100000); // Wait 100ms before retry
                continue;
            }

            // Update fixed key with incrementing value
            cuckoo_hash_key_t key_data = fixed_keys[current_key_index];
            cuckoo_hash_value_t value = 100 + (update_count % 900); // Values from 100-999

            struct cuckoo_hash_parameters params = {
                .hash_table = (struct cuckoo_hash*)&local_hash_tab.cuckoo_hash,
                .bfs_queue = &bfs_queue,
            };

            ret = cuckoo_hash_update_elem(&params, &key_data, &value);
            if (ret == 0) {
                insertions++;
                operations++;
            } else if (ret == -ENOSPC) {
                printf("Hash table is full (ENOSPC)\n");
            } else if (ret == -EINVAL) {
                printf("Invalid parameters (EINVAL)\n");
            } else {
                printf("Failed to update key-value pair: %d\n", ret);
            }

            // Update the map with syscall method
            ret = bpf_map_update_elem(map_fd, &key, &local_hash_tab, 0);
            if (ret != 0) {
                printf("Failed to update kernel map: %d\n", ret);
            }
        }

        // Move to next key and increment update counter
        current_key_index = (current_key_index + 1) % CUCKOO_HASH_ENTRIES;
        update_count++;

        // Print statistics periodically only in verbose mode
        if (verbose && operations % 10 == 0) {
            printf("Operations: %d, Insertions: %d, Success rate: %.2f%%, Key: %d/%d, Value: %d, Updates: %d\n",
                   operations, insertions, (float)insertions/operations*100,
                   current_key_index, CUCKOO_HASH_ENTRIES, 100 + (update_count % 900), update_count);
        }

        // Control insertion frequency
        usleep(insertion_frequency);
    }

    // Cleanup
    if (use_shared_memory && map_mmaped) {
        munmap(map_mmaped, map_sz);
    }
    close(map_fd);
    printf("Update loop stopped. Total operations: %d, Total insertions: %d, Total updates: %d\n",
           operations, insertions, update_count);
}

static void print_usage(const char *prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  -f, --frequency FREQ    Insertion frequency in microseconds (default: 1000000)\n");
    printf("  -c, --cpu-core CORE     Pin to specific CPU core (default: -1, no pinning)\n");
    printf("  -v, --verbose          Enable verbose output (default: quiet mode)\n");
    printf("  -h, --help             Show this help message\n");
    printf("\nNotes:\n");
    printf("  This program loads the BPF skeleton and pins the map automatically.\n");
    printf("  Map will be pinned to %s\n", PIN_PATH);
    printf("  Press Ctrl+C to stop the update loop.\n");
    printf("  Default mode is quiet (no periodic statistics printed).\n");
    printf("\nCPU Core Pinning:\n");
    printf("  Use -c option to pin to a specific CPU core for better performance.\n");
    printf("  Core IDs start from 0. Use -1 for no CPU affinity (default).\n");
}

int main(int argc, char *argv[])
{
    int insertion_frequency = 1000000; // Default: 1 second
    int cpu_core = -1; // Default: no CPU core pinning
    int verbose = 0; // Default: quiet mode

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
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
            printf("Verbose mode enabled\n");
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

    printf("Starting cuckoo hash update loop...\n");
    printf("Insertion frequency: %d microseconds\n", insertion_frequency);
    if (cpu_core >= 0) {
        printf("CPU core pinning: %d\n", cpu_core);
    } else {
        printf("CPU core pinning: disabled\n");
    }
    if (!verbose) {
        printf("Quiet mode enabled (use -v for verbose output)\n");
    }

    // Run the update loop
    update_loop(insertion_frequency, cpu_core, verbose);

    printf("Program exited gracefully.\n");
    return 0;
}