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
#include <sys/file.h>
#include <sched.h>
#include <unistd.h>
#include <sys/sysinfo.h>

#define PIN_PATH "/sys/fs/bpf/cuckoo_hash_map"
#define PID_FILE "/tmp/cuckoo_hash_daemon.pid"

volatile sig_atomic_t running = 1;

// Signal handler for graceful shutdown
static void handle_sigterm(int sig) {
    printf("Daemon received SIGTERM, shutting down gracefully...\n");
    running = 0;
}

static void handle_sigint(int sig) {
    printf("Daemon received SIGINT, shutting down gracefully...\n");
    running = 0;
}

// Function to get pinned map's file descriptor
static int get_pinned_map_fd() {
    int fd = bpf_obj_get(PIN_PATH);
    if (fd < 0) {
        printf("Failed to get pinned map: %s\n", strerror(errno));
        return -1;
    }
    return fd;
}

// Function to pin map to BPF filesystem
static int pin_map_to_bpf_fs(struct bpf_map *map) {
    // Remove existing pinned map if it exists
    unlink(PIN_PATH);

    // Create the directory if it doesn't exist
    mkdir("/sys/fs/bpf", 0700);

    // Pin the map
    if (bpf_map__pin(map, PIN_PATH) != 0) {
        printf("Failed to pin map: %s\n", strerror(errno));
        return -1;
    }

    printf("Map pinned to %s\n", PIN_PATH);
    return 0;
}

// Function to write PID file
static int write_pid_file(pid_t pid) {
    int fd = open(PID_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        printf("Failed to open PID file: %s\n", strerror(errno));
        return -1;
    }

    // Exclusive lock to prevent multiple instances
    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        if (errno == EWOULDBLOCK) {
            printf("Another instance is already running\n");
        } else {
            printf("Failed to lock PID file: %s\n", strerror(errno));
        }
        close(fd);
        return -1;
    }

    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%d\n", pid);
    if (write(fd, pid_str, strlen(pid_str)) < 0) {
        printf("Failed to write PID file: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    // Keep file open to maintain lock
    return fd;
}

// Function to cleanup PID file
static void cleanup_pid_file(int fd) {
    if (fd >= 0) {
        flock(fd, LOCK_UN);
        close(fd);
    }
    unlink(PID_FILE);
}

// Function to generate random 5-tuple key
static void generate_random_key(cuckoo_hash_key_t *key) {
    key->pkt.src_ip = rand() % 0xFFFFFFFF;
    key->pkt.dst_ip = rand() % 0xFFFFFFFF;
    key->pkt.src_port = rand() % 0xFFFF;
    key->pkt.dst_port = rand() % 0xFFFF;
    key->pkt.proto = (rand() % 3) + 1; // TCP, UDP, or ICMP
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

// Daemon update loop function
static void daemon_update_loop(int insertion_frequency, int cpu_core) {
    struct cuckoo_hash hash_tab = {0};
    struct __cuckoo_hash_bfs_queue bfs_queue = {0};
    struct cuckoo_hash_parameters params = {
        .hash_table = &hash_tab,
        .bfs_queue = &bfs_queue,
    };

    // Get map file descriptor
    int map_fd = get_pinned_map_fd();
    if (map_fd < 0) {
        return;
    }

    // Pin to specific CPU core if requested
    if (cpu_core >= 0) {
        if (pin_to_cpu_core(cpu_core) != 0) {
            printf("Warning: Failed to pin to CPU core %d, continuing without CPU affinity\n", cpu_core);
        }
    }

    printf("Daemon started (PID: %d)\n", getpid());
    printf("Insertion frequency: %d microseconds\n", insertion_frequency);
    if (cpu_core >= 0) {
        printf("Pinned to CPU core: %d\n", cpu_core);
    }

    int operations = 0;
    int insertions = 0;

    while (running) {
        // Get current cuckoo hash table from kernel
        int key = 0;
        int ret = bpf_map_lookup_elem(map_fd, &key, &hash_tab);
        if (ret != 0) {
            printf("Failed to lookup cuckoo hash map, ret %d: %s\n", ret, strerror(errno));
            usleep(100000); // Wait 100ms before retry
            continue;
        }

        // Insert random key-value pair
        cuckoo_hash_key_t key_data;
        cuckoo_hash_value_t value = rand() % 0xFFFFFFFF;
        generate_random_key(&key_data);

        ret = cuckoo_hash_update_elem(&params, &key_data, &value);
        if (ret == 0) {
            insertions++;
            operations++;
        } else if (ret == -ENOSPC) {
            printf("Hash table is full (ENOSPC)\n");
        } else if (ret == -EINVAL) {
            printf("Invalid parameters (EINVAL)\n");
        } else {
            printf("Failed to insert key-value pair: %d\n", ret);
        }

        // Write back to kernel map
        ret = bpf_map_update_elem(map_fd, &key, &hash_tab, 0);
        if (ret != 0) {
            printf("Failed to update kernel map: %d\n", ret);
        }

        // Print statistics periodically
        if (operations % 10 == 0) {
            printf("Operations: %d, Insertions: %d, Success rate: %.2f%%\n",
                   operations, insertions, (float)insertions/operations*100);
        }

        // Control insertion frequency
        usleep(insertion_frequency);
    }

    close(map_fd);
    printf("Daemon stopped. Total operations: %d, Total insertions: %d\n",
           operations, insertions);
}

static void print_usage(const char *prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  -f, --frequency FREQ    Insertion frequency in microseconds (default: 1000000)\n");
    printf("  -c, --cpu-core CORE     Pin daemon to specific CPU core (default: -1, no pinning)\n");
    printf("  -n, --no-update-loop    Load BPF program and exit without starting daemon\n");
    printf("  -h, --help             Show this help message\n");
    printf("\nDaemon Control:\n");
    printf("  After starting, the main process will exit and the daemon will run in background.\n");
    printf("  To stop the daemon: kill -TERM <PID> or kill -INT <PID>\n");
    printf("  Or use: kill $(cat /tmp/cuckoo_hash_daemon.pid)\n");
    printf("\nCPU Core Pinning:\n");
    printf("  Use -c option to pin the daemon to a specific CPU core for better performance.\n");
    printf("  Core IDs start from 0. Use -1 for no CPU affinity (default).\n");
}

static int callback_after_load(void *skel)
{
    struct ebpf_cuckoo_hash_dp *s = (struct ebpf_cuckoo_hash_dp *)skel;

    printf("Callback after load: pinning map to BPF filesystem...\n");

    // Pin the map to BPF filesystem
    if (pin_map_to_bpf_fs(s->maps.cuckoo_hash_map) != 0) {
        printf("Failed to pin map in callback_after_load\n");
        return -1;
    }

    return 0;
}

// Function to load BPF program and return result
static int load_bpf_program(void) {
    BPF_XDP_SKEL_LOADER_WITH_AFTER_LOAD(ebpf_cuckoo_hash_dp, XDP_IF, xdp_main, callback_after_load, XDP_FLAGS_SKB_MODE);
}

int main(int argc, char *argv[])
{
    int insertion_frequency = 1000000; // Default: 1 second
    int disable_update_loop = 0; // Flag to disable update loop
    int cpu_core = -1; // Default: no CPU core pinning (-1)

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--no-update-loop") == 0) {
            disable_update_loop = 1;
            printf("Update loop disabled - will load BPF program and exit\n");
        } else if ((strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--frequency") == 0) && i + 1 < argc) {
            insertion_frequency = atoi(argv[++i]);
            if (insertion_frequency < 100000 || insertion_frequency > 10000000) {
                printf("Invalid frequency. Using default (1000000 microseconds).\n");
                printf("Frequency must be between 100000 and 10000000 microseconds.\n");
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
                printf("Will pin daemon to CPU core %d\n", cpu_core);
            }
        } else {
            printf("Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    // Load BPF program and pin map (common for both modes)
    int bpf_load_result = load_bpf_program();

    if (bpf_load_result != 0) {
        printf("Failed to load BPF program and pin map\n");
        return 1;
    }

    if (disable_update_loop) {
        printf("✅ BPF program loaded and map pinned successfully.\n");
        printf("📍 Map pinned to: %s\n", PIN_PATH);
        printf("🚀 No daemon started - program will exit now.\n");

        return 0;
    } else {
        printf("Starting cuckoo hash control plane daemon...\n");
        printf("Insertion frequency: %d microseconds\n", insertion_frequency);
        if (cpu_core >= 0) {
            printf("CPU core pinning: %d\n", cpu_core);
        } else {
            printf("CPU core pinning: disabled\n");
        }

        printf("BPF program loaded and map pinned.\n");

        // Fork to create daemon process
        pid_t pid = fork();
        if (pid < 0) {
            printf("Failed to fork daemon process: %s\n", strerror(errno));
            return 1;
        } else if (pid == 0) {
            // Child process - become daemon
            // Create new session
            if (setsid() < 0) {
                printf("Failed to create new session: %s\n", strerror(errno));
                exit(1);
            }

            // Change working directory to root
            if (chdir("/") < 0) {
                printf("Failed to change directory: %s\n", strerror(errno));
                exit(1);
            }

            // Set umask
            umask(0);

            // Close standard file descriptors
            close(STDIN_FILENO);
            close(STDOUT_FILENO);
            close(STDERR_FILENO);

            // Reopen stderr for logging (optional)
            freopen("/tmp/cuckoo_hash_daemon.log", "a", stderr);

            // Write PID file
            int pid_fd = write_pid_file(getpid());
            if (pid_fd < 0) {
                exit(1);
            }

            // Set up signal handlers
            struct sigaction sa_term, sa_int;

            sa_term.sa_handler = handle_sigterm;
            sigemptyset(&sa_term.sa_mask);
            sa_term.sa_flags = 0;
            sigaction(SIGTERM, &sa_term, NULL);

            sa_int.sa_handler = handle_sigint;
            sigemptyset(&sa_int.sa_mask);
            sa_int.sa_flags = 0;
            sigaction(SIGINT, &sa_int, NULL);

            // Run daemon update loop
            daemon_update_loop(insertion_frequency, cpu_core);

            // Cleanup
            cleanup_pid_file(pid_fd);
            exit(0);
        } else {
            // Parent process - print instructions and exit
            printf("\n✅ Cuckoo hash daemon started successfully!\n");
            printf("📝 Daemon PID: %d\n", pid);
            printf("📍 PID file: %s\n", PID_FILE);
            printf("📋 Log file: /tmp/cuckoo_hash_daemon.log\n");
            printf("\n🛑 To stop the daemon, use one of these commands:\n");
            printf("   kill -TERM %d\n", pid);
            printf("   kill -INT %d\n", pid);
            printf("   kill $(cat %s)\n", PID_FILE);
            printf("\n📊 To view daemon logs:\n");
            printf("   tail -f /tmp/cuckoo_hash_daemon.log\n");
            printf("\n🔍 To check if daemon is running:\n");
            printf("   ps aux | grep cuckoo_hash\n");
            printf("   cat %s\n", PID_FILE);
            printf("\nMain process exiting. Daemon will continue running in background.\n");

            // Give daemon a moment to start
            usleep(1000000); // 1 second

            // Check if daemon started successfully
            if (kill(pid, 0) == 0) {
                printf("✅ Daemon is running (PID: %d)\n", pid);
            } else {
                printf("❌ Daemon failed to start\n");
                return 1;
            }

            return 0;
        }
    }
}