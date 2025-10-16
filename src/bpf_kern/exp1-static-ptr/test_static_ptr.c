#include "../common.h"
#include "static_ptr.h"
#include "static_ptr_skiplist.h"

char _license[] SEC("license") = "GPL";

PACKET_COUNT_MAP_DEFINE

#define KEY_RANGE 4096

__u64 skiplist_head_idx = 0;

static long insert_callback(__u32 index, void *data)
{
	struct eNetSTL_container *container = bpf_enetstl_get_nodes(proxy_fd);
	if (container == NULL) {
		log_error("[SKIP LIST] Failed to get node container");
		return 1;
	}
	if (container->free_list_head == container->capacity) {
		log_debug("[SKIP LIST] No free nodes available in container, try to enlarge capacity");
		bpf_enetstl_enlarge_capacity(container);
		container = bpf_enetstl_get_nodes(proxy_fd);  //get new container
		if (container == NULL) {
			log_error("[SKIP LIST] Failed to get node container after enlarge capacity");
			return 1;
		}
	}
	skip_key_type_t pkt_with_pad = {0};
	__builtin_memset(&pkt_with_pad, 0, sizeof(pkt_with_pad));
	skip_value_type_t value_with_pad = {0};
	__builtin_memset(&value_with_pad, 0, sizeof(value_with_pad));
	int key = index; // Convert 0-based index to 1-based key

	pkt_with_pad.key = key;
	value_with_pad.data = key;
	log_debug("[SKIP LIST] try to inserted key: %d", key);
	long res = skip_list_update_elem(container, 
		skiplist_head_idx, &pkt_with_pad, &value_with_pad);
	if (res != 0) {
		log_error("Failed to insert key: %d, res: %ld", key, res);
		bpf_enetstl_put_nodes(container);
		return 1;
	}
	log_info("[SKIP LIST] Inserted key: %d", key);
	bpf_enetstl_put_nodes(container);
	return 0;
}

/* Syscall program for updating*/
SEC("syscall")
int arena_skiplist_init(void *ctx)
{
	/* create proxy */
	struct eNetSTL_proxy *proxy = bpf_enetstl_create_node_proxy();
	if (proxy == NULL) {
		log_error("[SKIP LIST] Failed to create node proxy");
		return -1;
	}
	proxy_fd = proxy->fd;
	log_debug("Created node proxy with fd: %d", proxy->fd);
	if (store_proxy_into_map(proxy) != 0) {
		log_error("[SKIP LIST] Failed to store proxy into map");
		bpf_enetstl_destroy_node_proxy(proxy);
		return -1;
	}
	struct eNetSTL_container *container = bpf_enetstl_get_nodes(proxy_fd);
	if (container == NULL) {
		log_error("[SKIP LIST] Failed to get node container");
		return -1;
	}
	log_debug("Got node container with capacity: %llu", container->capacity);

	enetstl_node_type *skip_list_head = bpf_enetstl_alloc_node(container, &skiplist_head_idx);
	if (skip_list_head == NULL) {
		log_error("[SKIP LIST] bpf_alloc failed");
		goto error_free_container;
	}
	init_skiplist_head(skip_list_head);

	// Use bpf_loop to insert entries
	long res = bpf_loop(KEY_RANGE, insert_callback, NULL, 0);
	if (res != KEY_RANGE) {
		log_error("bpf_loop failed, returned: %ld", res);
		goto error_free_container;
	}
	// Initialize with just the head node - skip complex initialization for testing
	log_info("Arena skiplist head initialized successfully, height %d", skip_list_head->height);
	log_info("Arena skiplist initialized with %d entries", KEY_RANGE);
	bpf_enetstl_put_nodes(container);
	return 0;

error_free_container:;
	bpf_enetstl_put_nodes(container);
	return -1;
}

struct lookup_test_ctx {
	struct eNetSTL_container *container;
};

static long lookup_test_callback(__u32 index, void *data)
{
	struct lookup_test_ctx *ctx = (struct lookup_test_ctx *)data;
	skip_key_type_t pkt_with_pad = {0};
	__builtin_memset(&pkt_with_pad, 0, sizeof(pkt_with_pad));
	int key = index; // Use index as key (0-based)

	pkt_with_pad.key = key;
	log_debug("[LOOKUP TEST] Testing lookup for key: %d", key);
	// Perform lookup
	u64 lookup_res_idx = skip_list_lookup_elem(ctx->container, skiplist_head_idx, &pkt_with_pad);
	if (lookup_res_idx == NULL_NODE_IDX) {
		log_error("[LOOKUP TEST] Failed to find key: %d", key);
		return 1; // Stop iteration on failure
	}
	enetstl_node_type *lookup_res = bpf_enetstl_get_node(ctx->container, lookup_res_idx);
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
int arena_skiplist_lookup(void *__ctx)
{
	struct eNetSTL_container *container = bpf_enetstl_get_nodes(proxy_fd);
	if (container == NULL) {
		log_error("[LOOKUP TEST] Failed to get node container");
		return -1;
	}
	enetstl_node_type *skip_list_head = bpf_enetstl_get_node(
		container, skiplist_head_idx);
	if (skip_list_head->height != MAX_SKIPLIST_HEIGHT) {
		log_error("skip_list_head height %d != MAX_SKIPLIST_HEIGHT %d",
			  skip_list_head->height, MAX_SKIPLIST_HEIGHT);
		goto error;
	}
	log_debug("skip_list_head height %d", skip_list_head->height);

	// Perform lookup test from [0, KEY_RANGE) using bpf_loop, all lookup should success
	struct lookup_test_ctx ctx = {
		.container = container,
	};
	log_info("[LOOKUP TEST] Starting comprehensive lookup test for %d keys", KEY_RANGE);
	long res = bpf_loop(KEY_RANGE, lookup_test_callback, &ctx, 0);
	if (res != KEY_RANGE) {
		log_error("[LOOKUP TEST] bpf_loop failed or stopped early at iteration %ld", res);
		goto error;
	}

	log_info("[LOOKUP TEST] All %d lookup tests passed successfully", KEY_RANGE);
	bpf_enetstl_put_nodes(container);
	return 0;
error:;
	bpf_enetstl_put_nodes(container);
	return -1;
}