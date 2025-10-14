#include "../common.h"
#include "arena_skiplist.h"

char _license[] SEC("license") = "GPL";

PACKET_COUNT_MAP_DEFINE

#define KEY_RANGE 4096

struct sl_entry __arena *skip_list_head;

static long insert_callback(__u32 index, void *data)
{

	skip_key_type_t pkt_with_pad = {0};
	__builtin_memset(&pkt_with_pad, 0, sizeof(pkt_with_pad));
	skip_value_type_t value_with_pad = {0};
	__builtin_memset(&value_with_pad, 0, sizeof(value_with_pad));
	int key = index; // Convert 0-based index to 1-based key

	pkt_with_pad.key = key;
	value_with_pad.data = key;
	log_debug("[SKIL LIST] try to inserted key: %d", key);
	cast_kern(skip_list_head);
	long res = skip_list_update_elem(skip_list_head, &pkt_with_pad, &value_with_pad);
	if (res != 0) {
		log_error("Failed to insert key: %d, res: %ld", key, res);
		return 1;
	}
	log_info("[SKIP LIST] Inserted key: %d", key);
	return 0;
}

/* Syscall program for updating*/
SEC("syscall")
int arena_skiplist_init(void *ctx)
{
	skip_list_head = bpf_alloc(sizeof(sl_entry));
	if (skip_list_head == NULL) {
		log_error("[SKIP LIST] bpf_alloc failed");
		return -1;
	}
	init_skiplist_head(skip_list_head);
	cast_kern(skip_list_head);
	log_debug("skip_list_head address: %p", skip_list_head);
	cast_kern(skip_list_head);
	log_debug("skip_list_head height %d", skip_list_head->height);

	// Use bpf_loop to insert entries
	long res = bpf_loop(KEY_RANGE, insert_callback, NULL, 0);
	if (res != KEY_RANGE) {
		log_error("bpf_loop failed, returned: %ld", res);
		return -1;
	}

	// Initialize with just the head node - skip complex initialization for testing
	cast_kern(skip_list_head);
	log_info("Arena skiplist head initialized successfully, height %d", skip_list_head->height);
	log_info("Arena skiplist initialized with %d entries", KEY_RANGE);
	return 0;
}

static long lookup_test_callback(__u32 index, void *data)
{
	skip_key_type_t pkt_with_pad = {0};
	__builtin_memset(&pkt_with_pad, 0, sizeof(pkt_with_pad));
	int key = index; // Use index as key (0-based)

	pkt_with_pad.key = key;
	log_debug("[LOOKUP TEST] Testing lookup for key: %d", key);

	// Perform lookup
	sl_entry *lookup_res = skip_list_lookup_elem(skip_list_head, &pkt_with_pad);
	if (lookup_res == NULL) {
		log_error("[LOOKUP TEST] Failed to find key: %d", key);
		return 1; // Stop iteration on failure
	}

	cast_kern(lookup_res);
	log_debug("[LOOKUP TEST] Successfully found key: %d, value: %llu",
		  key, lookup_res->value.data);

	// Verify the value matches the key
	if (lookup_res->value.data != key) {
		log_error("[LOOKUP TEST] Value mismatch for key %d: expected %d, got %llu",
			  key, key, lookup_res->value.data);
		return 1; // Stop iteration on failure
	}

	return 0; // Continue
}

SEC("syscall")
int arena_skiplist_lookup(void *ctx)
{
	sl_entry *test_entry = bpf_alloc(sizeof(sl_entry));
	if (test_entry == NULL) {
		log_error("[SKIP LIST] bpf_alloc failed");
		return -1;
	}
	log_debug("skip_list_head address: %p", skip_list_head);
	cast_kern(skip_list_head);
	if (skip_list_head->height != MAX_SKIPLIST_HEIGHT) {
		log_error("skip_list_head height %d != MAX_SKIPLIST_HEIGHT %d",
			  skip_list_head->height, MAX_SKIPLIST_HEIGHT);
		return -1;
	}
	log_debug("skip_list_head height %d", skip_list_head->height);

	// Perform lookup test from [0, KEY_RANGE) using bpf_loop, all lookup should success
	log_info("[LOOKUP TEST] Starting comprehensive lookup test for %d keys", KEY_RANGE);
	long res = bpf_loop(KEY_RANGE, lookup_test_callback, NULL, 0);
	if (res != KEY_RANGE) {
		log_error("[LOOKUP TEST] bpf_loop failed or stopped early at iteration %ld", res);
		goto error;
	}

	log_info("[LOOKUP TEST] All %d lookup tests passed successfully", KEY_RANGE);
	return 0;
error:;
	return -1;
}