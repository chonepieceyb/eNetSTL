#include "../vmlinux.h"
#include "../common.h"
#include "cuckoo_hash.h"
#include "cuckoo_hash_map_defs.h"

char LICENSE[] SEC("license") = "GPL";
__u32 dummy;

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

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_PAIRS_ENTRIES);
	__type(key, int);
	__type(value, struct cuckoo_hash_pair);
	__uint(pinning, 1);
} cuckoo_hash_pairs_map SEC(".maps");

SEC("iter/bpf_map_elem")
int cuckoo_hash_inkernel_cp(struct bpf_iter__bpf_map_elem *ctx)
{
	__u32 *key = ctx->key;
	struct cuckoo_hash_pair *val = (struct cuckoo_hash_pair*)ctx->value;
        struct cuckoo_hash_parameters params;
        struct cuckoo_hash *h;
        struct __cuckoo_hash_bfs_queue *bfs_queue;
        int zero = 0;
        int ret  = 0;

	if (key == (void *)0 || val == (void *)0) {
                cuckoo_log(error, "iter: NULL key or value pointer");
                return 0;
        }

        if (val->updated == 1) {
                // this key have been updated
                return 0;
        }

        // Get hash table using new API
        h = get_cuckoo_hash(&cuckoo_hash_map);
        if (unlikely(h == NULL)) {
                cuckoo_log(error, "iter: cannot get cuckoo hash");
                return 0;
        }

        // Get BFS queue from map
        bfs_queue = bpf_map_lookup_elem(&__cuckoo_hash_bfs_queue_map, &zero);
        if (unlikely(bfs_queue == NULL)) {
                cuckoo_log(error, "iter: cannot get bfs queue");
                return 0;
        }

        params.hash_table = h;
        params.bfs_queue = bfs_queue;

        struct update_record record = { 
                .key = *key,
                .succeeded = 0
        };
        ret = cuckoo_hash_update_elem(&params, &(val->key), &(val->value));
        if (ret == 0) {
                record.succeeded = 1;
                cuckoo_log(debug, "iter: update key %u succeeded", *key);
        } else {
                record.succeeded = 0;
                cuckoo_log(error, "iter: update key %u failed: %d", *key, ret);
        }
        val->updated = 1;
        //update success
        
        bpf_seq_write(ctx->meta->seq, &record, sizeof(record));

        //all success 
        return 0;
}
