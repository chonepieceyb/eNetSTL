#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <linux/types.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include "../test_helpers.h"
#include "../config.h"
#include "../motivation-control-plane/cuckoo_hash_operations.h"

// Get cuckoo hash constants - use definitions from header
#define CUCKOO_HASH_KEY_SLOTS (CUCKOO_HASH_ENTRIES + 1)

//Test implementation of in-kernel control plane using BPF iter for bpf_kern/motivation-control-plane/ebpf_cuckoo_hash_cp_iter.h

// Fix type definitions for BPF skeleton
typedef __u32 u32;
typedef __u16 u16;
typedef __u8 u8;

#include "../bpf_skel/ebpf_cuckoo_hash_cp_iter.skel.h"

// Define structures from eBPF program
#define MAX_PAIRS_ENTRIES 16

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

#define PIN_PATH "/sys/fs/bpf/cuckoo_hash_map"

// Test data structures
static struct test_ebpf_cuckoo_hash_dp *test_skel = NULL;

// Global test state
static struct cuckoo_hash global_hash = {0};
static struct __cuckoo_hash_bfs_queue global_bfs_queue = {0};
static struct cuckoo_hash_parameters global_params = {
	.hash_table = &global_hash,
	.bfs_queue = &global_bfs_queue,
};

static int get_pinned_map_fd() {
    int fd = bpf_obj_get(PIN_PATH);
    if (fd < 0) {
        printf("Failed to get pinned map: %s\n", strerror(errno));
        return -1;
    }
    return fd;
}


static int test_call_inkernel_dp(void)
{
	struct ebpf_cuckoo_hash_cp_iter *iter_skel = NULL;
	struct bpf_link *link = NULL;
	union bpf_iter_link_info linfo = {0};
	LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	int iter_fd, ret, i, map_fd;
	char buf[4096];
	ssize_t len;
	int success_count = 0;

	printf("Testing in-kernel control plane using BPF iter...\n");

	// 1. open and load iter_skel
	iter_skel = ebpf_cuckoo_hash_cp_iter__open();
	if (!iter_skel) {
		printf("Failed to open iter skeleton\n");
		return -1;
	}

	// Load the BPF program first
	ret = ebpf_cuckoo_hash_cp_iter__load(iter_skel);
	if (ret != 0) {
		printf("Failed to load iter skeleton: %d\n", ret);
		goto cleanup;
	}

	// 2. generate test key-value pairs and populate cuckoo_hash_pairs_map
	map_fd = bpf_map__fd(iter_skel->maps.cuckoo_hash_pairs_map);
	if (map_fd < 0) {
		printf("Failed to get cuckoo_hash_pairs_map fd: %d\n", map_fd);
		goto cleanup;
	}

	// Generate test key-value pairs
	for (i = 0; i < MAX_PAIRS_ENTRIES; i++) {
		struct cuckoo_hash_pair pair = {0};
		int key = i;

		// Create test key
		pair.key.pkt.src_ip = htonl(0x0a000001 + i); // 10.0.0.1 + i
		pair.key.pkt.dst_ip = htonl(0x0a000064);     // 10.0.0.100
		pair.key.pkt.src_port = htons(1000 + i);
		pair.key.pkt.dst_port = htons(80);
		pair.key.pkt.proto = IPPROTO_TCP;

		// Set test value
		pair.value = i + 100;
		pair.updated = 0; // Mark as not updated yet

		ret = bpf_map_update_elem(map_fd, &key, &pair, BPF_ANY);
		if (ret != 0) {
			printf("Failed to update cuckoo_hash_pairs_map[%d]: %d\n", i, ret);
			goto cleanup;
		}
		printf("Added test pair %d: key=(%08x:%04x->%08x:%04x) value=%u\n",
		       i, ntohl(pair.key.pkt.src_ip), ntohs(pair.key.pkt.src_port),
		       ntohl(pair.key.pkt.dst_ip), ntohs(pair.key.pkt.dst_port), pair.value);
	}

	// 3. attach iter to the pairs map
	linfo.map.map_fd = map_fd;
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);

	link = bpf_program__attach_iter(iter_skel->progs.cuckoo_hash_inkernel_cp, &opts);
	if (!link) {
		printf("Failed to attach iter program\n");
		goto cleanup;
	}

	// 4. use read() to trigger the iter program
	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (iter_fd < 0) {
		printf("Failed to create iter fd: %d\n", iter_fd);
		goto cleanup;
	}

	printf("Triggering iter program...\n");

	// 5. read results from iter
	memset(buf, 0, sizeof(buf));
	len = read(iter_fd, buf, sizeof(buf) - 1);
	if (len < 0) {
		printf("Failed to read from iter: %s\n", strerror(errno));
		close(iter_fd);
		goto cleanup;
	}

	printf("Iter program completed, read %zd bytes\n", len);

	// Parse results and count successes
	struct update_record *record = (struct update_record *)buf;
	int num_records = len / sizeof(struct update_record);

	for (i = 0; i < num_records; i++) {
		if (record[i].succeeded) {
			success_count++;
			printf("Key %u: Update succeeded\n", record[i].key);
		} else {
			printf("Key %u: Update failed\n", record[i].key);
		}
	}

	printf("Summary: %d/%d updates succeeded\n", success_count, num_records);

	close(iter_fd);
	bpf_link__destroy(link);
	ebpf_cuckoo_hash_cp_iter__destroy(iter_skel);

	return (success_count == num_records) ? 0 : -1;

cleanup:
	if (link)
		bpf_link__destroy(link);
	if (iter_skel)
		ebpf_cuckoo_hash_cp_iter__destroy(iter_skel);
	return -1;
}

static int verify_cuckoo_hash_contents()
{
	int map_fd, ret, i;
	struct dummy_struct dummy;
	int zero = 0;

	printf("Verifying cuckoo hash contents...\n");

	// 1. get the pinned bpf map using get_pinned_map_fd()
	map_fd = get_pinned_map_fd();
	if (map_fd < 0) {
		printf("Failed to get pinned map\n");
		return -1;
	}

	// Get the dummy struct that contains the hash table
	ret = bpf_map_lookup_elem(map_fd, &zero, &dummy);
	if (ret != 0) {
		printf("Failed to lookup dummy struct: %d\n", ret);
		close(map_fd);
		return -1;
	}

	// Update global hash table reference to point to the actual hash table in the map
	global_hash = dummy.cuckoo_hash;

	// 2. check the cuckoo hash contents to verify all updates were applied correctly
	printf("Verifying hash table entries...\n");
	int found_count = 0;

	for (i = 0; i < MAX_PAIRS_ENTRIES; i++) {
		struct pkt_5tuple_with_pad search_key = {0};
		cuckoo_hash_value_t *found_value = NULL;

		// Create the same key we used in the test
		search_key.pkt.src_ip = htonl(0x0a000001 + i); // 10.0.0.1 + i
		search_key.pkt.dst_ip = htonl(0x0a000064);     // 10.0.0.100
		search_key.pkt.src_port = htons(1000 + i);
		search_key.pkt.dst_port = htons(80);
		search_key.pkt.proto = IPPROTO_TCP;

		// Search for the key in the hash table
		ret = cuckoo_hash_lookup_elem(&global_params, &search_key, &found_value);
		if (ret == 0 && found_value != NULL) {
			u32 expected_value = i + 100;
			if (*found_value == expected_value) {
				printf("Key %d: Found correct value %u\n", i, *found_value);
				found_count++;
			} else {
				printf("Key %d: Found incorrect value %u (expected %u)\n",
				       i, *found_value, expected_value);
			}
		} else {
			printf("Key %d: Not found in hash table (ret=%d)\n", i, ret);
		}
	}

	printf("Verification complete: %d/%d entries found with correct values\n",
	       found_count, MAX_PAIRS_ENTRIES);

	close(map_fd);
	return (found_count == MAX_PAIRS_ENTRIES) ? 0 : -1;
}

int main(void)
{
	int ret;

	printf("=== Cuckoo Hash In-Kernel Control Plane Test ===\n");

	// First, initialize the global hash table and BFS queue
	printf("Initializing global cuckoo hash...\n");
	memset(&global_hash, 0, sizeof(global_hash));
	memset(&global_bfs_queue, 0, sizeof(global_bfs_queue));

	// Initialize hash table (similar to get_cuckoo_hash logic)
	if (!global_hash.initialized) {
		int i;
		for (i = 1; i < CUCKOO_HASH_KEY_SLOTS; i++) {
			__cuckoo_hash_enqueue_slot_back(&global_hash, i);
		}
		global_hash.initialized = 1;
	}

	// 1. test_call_inkernel_dp
	printf("\n--- Testing in-kernel control plane ---\n");
	ret = test_call_inkernel_dp();
	if (ret != 0) {
		printf("ERROR: test_call_inkernel_dp failed\n");
		return 1;
	}
	printf("SUCCESS: test_call_inkernel_dp passed\n");

	// 2. verify_cuckoo_hash_contents
	printf("\n--- Verifying hash table contents ---\n");
	ret = verify_cuckoo_hash_contents();
	if (ret != 0) {
		printf("ERROR: verify_cuckoo_hash_contents failed\n");
		return 1;
	}
	printf("SUCCESS: verify_cuckoo_hash_contents passed\n");

	printf("\n=== All tests passed! ===\n");
	return 0;
}
