#include <string.h>
#include <bpf/libbpf.h>
#include <linux/types.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include "../test_helpers.h"
#include "../config.h"
#include "../motivation-control-plane/cuckoo_hash_operations.h"

// Get cuckoo hash constants - define directly to avoid header conflicts
#define CUCKOO_HASH_ENTRIES 512
#define CUCKOO_HASH_KEY_SLOTS (CUCKOO_HASH_ENTRIES + 1)

// Test implementation for cuckoo hash control-plane/data-plane interaction
// Tests BPF program in bpf_kern/motivation-control-plane/test_ebpf_cuckoo_hash_dp.c
// Key is TCP 5-tuple, populated in packet and passed to BPF_PROG_TEST_RUNNER_WITH_CALLBACK
// Map accessible via test_skel->maps.cuckoo_hash_map




// Fix type definitions for BPF skeleton
typedef __u32 u32;
typedef __u16 u16;
typedef __u8 u8;

#include "../bpf_skel/test_ebpf_cuckoo_hash_dp.skel.h"

// Test data structures
static struct test_ebpf_cuckoo_hash_dp *test_skel = NULL;
static int cuckoo_hash_map_fd = -1;
static int bfs_queue_map_fd = -1;

// Global test state
static struct cuckoo_hash global_hash = {0};
static struct __cuckoo_hash_bfs_queue global_bfs_queue = {0};
static struct cuckoo_hash_parameters global_params = {
	.hash_table = &global_hash,
	.bfs_queue = &global_bfs_queue,
};

// Forward declarations
static int setup_cuckoo_hash_params(struct cuckoo_hash_parameters *params);
static void cleanup_cuckoo_hash_params(struct cuckoo_hash_parameters *params);

// Packet structure that matches what eBPF parser expects
// eBPF parse_pkt_5tuple expects: ethhdr + iphdr + __ports (just src_port + dst_port)
struct test_packet {
	struct ethhdr eth;
	struct iphdr iph;
	struct __ports {
		__be16 src_port;
		__be16 dst_port;
	} ports;
} __attribute__((packed));

// Debug function to print packet structure
static void debug_packet_structure(const struct test_packet *pkt, const char *name) {
	printf("Debug %s packet:\n", name);
	printf("  eth.h_proto: 0x%04x (expected 0x%04x)\n", pkt->eth.h_proto, __bpf_constant_htons(ETH_P_IP));
	printf("  iph.version: %d, ihl: %d\n", pkt->iph.version, pkt->iph.ihl);
	printf("  iph.protocol: %d (expected %d)\n", pkt->iph.protocol, IPPROTO_TCP);
	printf("  iph.tot_len: %d\n", pkt->iph.tot_len);
	printf("  iph.saddr: 0x%08x, daddr: 0x%08x\n", pkt->iph.saddr, pkt->iph.daddr);
	printf("  ports.src_port: 0x%04x, dst_port: 0x%04x\n", pkt->ports.src_port, pkt->ports.dst_port);
	printf("  Total packet size: %zu bytes\n", sizeof(*pkt));
}

// Debug function to print tuple structure
static void debug_tuple_structure(const struct pkt_5tuple_with_pad *tuple, const char *name) {
	printf("Debug %s tuple:\n", name);
	printf("  src_ip: 0x%08x\n", tuple->pkt.src_ip);
	printf("  dst_ip: 0x%08x\n", tuple->pkt.dst_ip);
	printf("  src_port: 0x%04x\n", tuple->pkt.src_port);
	printf("  dst_port: 0x%04x\n", tuple->pkt.dst_port);
	printf("  proto: 0x%02x\n", tuple->pkt.proto);
	printf("  sizeof(tuple): %zu bytes\n", sizeof(*tuple));
}

static struct test_packet test_pkt_v4 = {
	.eth.h_proto = __bpf_constant_htons(ETH_P_IP),
	.iph.ihl = 5,
	.iph.version = 4,
	.iph.tos = 0,
	.iph.tot_len = __bpf_constant_htons(40),  // Full packet size for XDP
	.iph.id = __bpf_constant_htons(1234),
	.iph.frag_off = 0,
	.iph.ttl = 64,
	.iph.protocol = IPPROTO_TCP,
	.iph.check = 0,  // Will be calculated if needed
	.iph.saddr = __bpf_constant_htonl(0x0a000001),  // 10.0.0.1
	.iph.daddr = __bpf_constant_htonl(0x0a000002),  // 10.0.0.2
	.ports.src_port = 0x3930,  // 12345 in network byte order (0x3039 -> 0x3930)
	.ports.dst_port = 0x0050,  // 80 in network byte order (0x0050)
};

static u32 test_value1 = 43;

static struct test_packet test_pkt_v4_2 = {
	.eth.h_proto = __bpf_constant_htons(ETH_P_IP),
	.iph.ihl = 5,
	.iph.version = 4,
	.iph.tos = 0,
	.iph.tot_len = __bpf_constant_htons(40),  // Full packet size for XDP
	.iph.id = __bpf_constant_htons(5678),
	.iph.frag_off = 0,
	.iph.ttl = 64,
	.iph.protocol = IPPROTO_TCP,
	.iph.check = 0,  // Will be calculated if needed
	.iph.saddr = __bpf_constant_htonl(0x0a000003),  // 10.0.0.3
	.iph.daddr = __bpf_constant_htonl(0x0a000004),  // 10.0.0.4
	.ports.src_port = 0xd483,  // 54321 in network byte order (0x83d4 -> 0xd483)
	.ports.dst_port = 0x01bb,  // 443 in network byte order (0x01bb)
};

static u32 test_value2 = 53;

// Convert test_packet to pkt_5tuple_with_pad
static void ipv4_packet_to_5tuple(const struct test_packet *pkt, struct pkt_5tuple_with_pad *tuple)
{
	tuple->pkt.src_ip = ntohl(pkt->iph.saddr);
	tuple->pkt.dst_ip = ntohl(pkt->iph.daddr);
	// Convert ports to host byte order to match what eBPF program produces
	tuple->pkt.src_port = ntohs(pkt->ports.src_port);
	tuple->pkt.dst_port = ntohs(pkt->ports.dst_port);
	tuple->pkt.proto = pkt->iph.protocol;
	memset(tuple->__pad, 0, sizeof(tuple->__pad));

	// Debug: Print the actual values in the packet structure
	printf("Debug: Packet structure values - src_port=0x%04x dst_port=0x%04x (raw bytes)\n",
	       pkt->ports.src_port, pkt->ports.dst_port);
	printf("Debug: Tuple values - src_port=0x%04x dst_port=0x%04x (copied to tuple)\n",
	       tuple->pkt.src_port, tuple->pkt.dst_port);
}


// Helper function to create cuckoo hash parameters for user-space operations
static int setup_cuckoo_hash_params(struct cuckoo_hash_parameters *params)
{
	int key = 0;
	// TODO: use bpf_map__lookup_elem
	if (bpf_map__lookup_elem(test_skel->maps.cuckoo_hash_map, &key, sizeof(key), params->hash_table, sizeof(*params->hash_table), 0) != 0) {
		fprintf(stderr, "Failed to lookup hash table\n");
		return -1;
	}
	// Get BFS queue from map
	if (bpf_map__lookup_elem(test_skel->maps.__cuckoo_hash_bfs_queue_map, &key, sizeof(key), params->bfs_queue, sizeof(*params->bfs_queue), 0) != 0) {
		fprintf(stderr, "Failed to lookup BFS queue\n");
		return -1;
	}
	return 0;
}


static int test_callback_before_load(void *skel)
{
	test_skel = (struct test_ebpf_cuckoo_hash_dp *)skel;

	// Initialize test data in BSS
	test_skel->bss->lookup_value = test_value1;  //TODO: fix: lookup be set before loading because if we load, change BSS 
	test_skel->bss->update_value = test_value2;
	struct pkt_5tuple_with_pad test_tuple = {0};
	ipv4_packet_to_5tuple(&test_pkt_v4_2, &test_tuple);
	memcpy(&test_skel->bss->update_pkt_key, &test_tuple, sizeof(test_skel->bss->update_pkt_key)); // for update in eBPF
	printf("Test skeleton BSS initialized\n");
	return 0;
}

static int test_callback_after_load(void *skel)
{
	int key = 0;
	int ret;

	// Initialize cuckoo hash map
	cuckoo_hash_map_fd = bpf_map__fd(test_skel->maps.cuckoo_hash_map);
	bfs_queue_map_fd = bpf_map__fd(test_skel->maps.__cuckoo_hash_bfs_queue_map);

	if (cuckoo_hash_map_fd < 0 || bfs_queue_map_fd < 0) {
		fprintf(stdout, "Failed to get map file descriptors\n");
		return -1;
	}

	// Setup global parameters
	if (setup_cuckoo_hash_params(&global_params) == 0) {
		printf("BPF maps and global parameters initialized successfully\n");
	} else {
		printf("Warning: Failed to setup global parameters\n");
		return -1;
	}
	// Initialize cuckoo hash table properly
	if (!global_params.hash_table->initialized) {
		printf("Debug: Initializing cuckoo hash table\n");
		global_params.hash_table->initialized = 1;
		SIMPLE_RINGBUF_CLEAR(&global_params.hash_table->free_slot_list);

		// Initialize all buckets to empty
		for (int i = 0; i < CUCKOO_HASH_NUM_BUCKETS; i++) {
			for (int j = 0; j < CUCKOO_HASH_BUCKET_ENTRIES; j++) {
				global_params.hash_table->buckets[i].sig_current[j] = 0;
				global_params.hash_table->buckets[i].key_idx[j] = CUCKOO_HASH_EMPTY_SLOT;
			}
		}

		// Initialize key store
		for (int i = 0; i < CUCKOO_HASH_KEY_SLOTS; i++) {
			global_params.hash_table->key_store[i].value = 0;
			memset(&global_params.hash_table->key_store[i].key, 0, sizeof(struct pkt_5tuple_with_pad));
		}

		// Initialize free slot list with available slots (1 to CUCKOO_HASH_KEY_SLOTS-1)
		for (int i = 1; i < CUCKOO_HASH_KEY_SLOTS; i++) {
			u32 *slot = cuckoo_hash_free_slots__simple_rbuf_prod(&global_params.hash_table->free_slot_list);
			if (slot != NULL) {
				*slot = i;
				cuckoo_hash_free_slots__simple_rbuf_submit(&global_params.hash_table->free_slot_list);
			}
		}
		printf("Debug: Cuckoo hash table initialized with %d slots\n", CUCKOO_HASH_KEY_SLOTS - 1);
	}

	//udpate map elem here
	// Insert entry from user-space
	printf(" Inserting entry from user-space\n");
	struct pkt_5tuple_with_pad test_tuple = {0};
	ipv4_packet_to_5tuple(&test_pkt_v4, &test_tuple);

	// Debug: Print the key being inserted
	printf("Debug: Inserting key - src_ip=0x%08x src_port=0x%04x dst_ip=0x%08x dst_port=0x%04x proto=0x%02x\n",
	       test_tuple.pkt.src_ip, test_tuple.pkt.src_port,
	       test_tuple.pkt.dst_ip, test_tuple.pkt.dst_port, test_tuple.pkt.proto);
	debug_tuple_structure(&test_tuple, "Inserted");

	ret = cuckoo_hash_update_elem(&global_params, &test_tuple, &test_value1);
	if (ret != 0) {
		fprintf(stderr, "Failed to update cuckoo hash from user-space: %d\n", ret);
		return -1;
	}
	printf("Successfully inserted entry with value %d\n", test_value1);

	// Debug: Print bucket contents for the inserted key
	printf("Debug: Key size: %zu bytes\n", sizeof(test_tuple));
	printf("Debug: Key first 4 bytes: 0x%02x%02x%02x%02x\n",
	       ((u8*)&test_tuple)[0], ((u8*)&test_tuple)[1], ((u8*)&test_tuple)[2], ((u8*)&test_tuple)[3]);
	u32 hash_val = __cuckoo_hash_hash(global_params.hash_table, &test_tuple);

	u16 short_sig = __cuckoo_hash_get_short_sig(hash_val);
	u32 prim_bkt = __cuckoo_hash_get_prim_bucket_index(global_params.hash_table, hash_val);
	u32 sec_bkt = __cuckoo_hash_get_alt_bucket_index(global_params.hash_table, prim_bkt, hash_val);

	printf("Debug: User-space hash: hash=0x%08x, short_sig=0x%04x, prim_bkt=%d, sec_bkt=%d\n",
	       hash_val, short_sig, prim_bkt, sec_bkt);

	// Print primary bucket contents
	printf("Debug: Primary bucket %d contents:\n", prim_bkt);
	for (int j = 0; j < CUCKOO_HASH_BUCKET_ENTRIES; j++) {
		u16 sig = global_params.hash_table->buckets[prim_bkt].sig_current[j];
		u32 key_idx = global_params.hash_table->buckets[prim_bkt].key_idx[j];
		printf("  Entry %d: sig=0x%04x, key_idx=%d\n", j, sig, key_idx);
		if (key_idx != CUCKOO_HASH_EMPTY_SLOT && key_idx < CUCKOO_HASH_KEY_SLOTS) {
			struct pkt_5tuple_with_pad *key = &global_params.hash_table->key_store[key_idx].key;
			u32 val = global_params.hash_table->key_store[key_idx].value;
			printf("    Key: src_ip=0x%08x src_port=0x%04x dst_ip=0x%08x dst_port=0x%04x proto=0x%02x, val=%d\n",
			       key->pkt.src_ip, key->pkt.src_port, key->pkt.dst_ip, key->pkt.dst_port, key->pkt.proto, val);
		}
	}

	// Write changes back to BPF map so eBPF program can see them
	int update_result = bpf_map_update_elem(cuckoo_hash_map_fd, &key, global_params.hash_table, 0); //TODO: use bpf_map__update_elem
	if (update_result != 0) {
		fprintf(stderr, "Failed to write hash table back to BPF map: %s (errno=%d)\n", strerror(errno), errno);
		return -1;
	} else {
		printf("Debug: Successfully wrote hash table to BPF map before eBPF lookup\n");
	}
	return 0;
}

static int test_callback_after_run(void *skel, int run_result, int prog_retval)
{
	if (run_result != 0) {
		fprintf(stdout, "%s:FAIL:bpf_prog_test_run_opts result: unexpected error: %d (errno %d)\n",
			__func__, run_result, errno);
		return -1;
	}
	// For XDP programs, XDP_PASS = 2, XDP_DROP = 0
	if (prog_retval != XDP_PASS) {
		fprintf(stdout, "%s:FAIL:bpf program return value: unexpected %d\n", __func__, prog_retval);
		return -1;
	}

	// Setup  parameters
	if (setup_cuckoo_hash_params(&global_params) == 0) {
		printf("BPF maps and global parameters initialized successfully\n");
	} else {
		printf("Warning: Failed to setup global parameters\n");
		return -1;
	}
	// try to lookup the value inserted by eBPF program
	u32 *value;
	int ret = cuckoo_hash_lookup_elem(&global_params, &test_skel->bss->update_pkt_key, &value);
	if (ret == 0) {
		printf("Successfully looked up entry inserted by eBPF program: value=%d\n", *value);
		if (*value != test_value2) {
			fprintf(stdout, "%s:FAIL:lookup value mismatch: expected %d, got %d\n",
				__func__, test_value2, *value);
			return -1;
		} else {
			printf("Lookup value matches expected value %d\n", test_value2);
		}
	} else {
		fprintf(stdout, "%s:FAIL:cannot find entry inserted by eBPF program: %d\n",
			__func__, ret);
		return -1;
	}
	return 0;
}


int testing(void){
	BPF_PROG_TEST_RUNNER_WITH_CALLBACK(
		"cuckoo_hash_dp_test",
		test_ebpf_cuckoo_hash_dp,
		test_pkt_v4,
		xdp_main,
		1,
		test_callback_before_load,
		test_callback_after_load,
		test_callback_after_run,
		XDP_PASS);
}

int main(void)
{
	printf("Starting cuckoo hash control-plane/data-plane tests...\n");
	printf("This test demonstrates the interaction between:\n");
	printf("1. User-space cuckoo hash operations\n");
	printf("2. eBPF program cuckoo hash operations\n");
	printf("3. Cross-plane data consistency\n\n");

	if (testing() == 0) {
		printf("\nAll tests PASSED\n");
	} else {
		printf("\nSome tests FAILED\n");
	}
}
