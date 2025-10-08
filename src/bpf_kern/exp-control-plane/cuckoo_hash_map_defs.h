#include "../vmlinux.h"
#include "../common.h"
#include "cuckoo_hash.h"

struct dummy_struct {
	struct cuckoo_hash cuckoo_hash;
	struct __cuckoo_hash_key padd1[PADD_SIZE];
	struct __cuckoo_hash_bucket padd2[PADD_SIZE];
};

// BPF map definitions
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct dummy_struct);
	__uint(pinning, 1);
} cuckoo_hash_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct __cuckoo_hash_bfs_queue);
	__uint(pinning, 1);
} __cuckoo_hash_bfs_queue_map SEC(".maps");

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