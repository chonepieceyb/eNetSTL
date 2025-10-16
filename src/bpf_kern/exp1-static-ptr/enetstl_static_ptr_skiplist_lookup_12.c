#include "../common.h"
#include "static_ptr.h"
#include "static_ptr_skiplist.h"

char _license[] SEC("license") = "GPL";

PACKET_COUNT_MAP_DEFINE

#ifndef KEY_RANGE
#define KEY_RANGE 4096
#endif 

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
int skiplist_init(void *ctx)
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

/* lookup program */
SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	LATENCY_START_TIMESTAMP_DEFINE

	skip_key_type_t pkt_with_pad = {0};
	skip_value_type_t value_with_pad = {0};

	pkt_with_pad.key = (bpf_get_prandom_u32() % KEY_RANGE);

	int key = 0;
	struct skip_list_proxy_map_value *val = bpf_map_lookup_elem(&skiplist_map, &key);
	if (val == NULL) {
		return -1;
	}

    	struct eNetSTL_container *container = bpf_enetstl_get_nodes(proxy_fd);
	if (container == NULL) {
		log_error("[LOOKUP TEST] Failed to get node container");
		return -1;
	}

	// Perform lookup
	__u64 lookup_idx = skip_list_lookup_elem(container, skiplist_head_idx,
							   &pkt_with_pad);
	if (lookup_idx == NULL_NODE_IDX) {
		log_error("lookup_key: %d, lookup failed", pkt_with_pad.key);
		goto error;
	}
	
    	bpf_enetstl_put_nodes(container);
	PACKET_COUNT_MAP_UPDATE

#ifdef LATENCY_EXP
	SWAP_MAC_AND_RETURN_XDP_TX(ctx) 
#endif
	return XDP_DROP;
error:;
    	bpf_enetstl_put_nodes(container);
	return XDP_DROP;
}