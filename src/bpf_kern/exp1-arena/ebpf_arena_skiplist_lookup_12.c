#include "../common.h"
#include "arena_skiplist.h"

char _license[] SEC("license") = "GPL";

void bpf_arena_empty(void *map)__ksym;

PACKET_COUNT_MAP_DEFINE

#define KEY_RANGE 4096

struct sl_entry __arena *skip_list_head;

static long insert_callback(__u32 index, void *data)
{
	skip_key_type_t pkt_with_pad = {0};
	skip_value_type_t value_with_pad = {0};
	int key = index; // Convert 0-based index to 1-based key

	pkt_with_pad.key = key;
	value_with_pad.data = key;
	cast_kern(skip_list_head);
	long res = skip_list_update_elem(skip_list_head, &pkt_with_pad, &value_with_pad);
	if (res != 0) {
		log_error("Failed to insert key: %d, res: %ld", key, res);
		return 1;
	}
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

/* lookup program */
SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	LATENCY_START_TIMESTAMP_DEFINE

	bpf_arena_empty(&arena);
	skip_key_type_t pkt_with_pad = {0};
	skip_value_type_t value_with_pad = {0};

	pkt_with_pad.key = (bpf_get_prandom_u32() % KEY_RANGE);

	// Perform lookup
	sl_entry *lookup_res = skip_list_lookup_elem(skip_list_head,
							   &pkt_with_pad);
	if (lookup_res == NULL) {
		log_error("lookup_key: %d, lookup failed", pkt_with_pad.key);
		goto error;
	}
	cast_kern(lookup_res);

	log_debug("lookup_key: %d, lookup success, value: %llu",
		  pkt_with_pad.key, lookup_res->value.data);


	PACKET_COUNT_MAP_UPDATE

#ifdef LATENCY_EXP
	SWAP_MAC_AND_RETURN_XDP_TX(ctx) 
#endif
	return XDP_DROP;
error:;
	return XDP_DROP;
}