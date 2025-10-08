#include "../vmlinux.h"
#include "../common.h"
#include "cuckoo_hash.h"

struct dummy_struct {
	struct cuckoo_hash cuckoo_hash;
	struct __cuckoo_hash_key padd1[65536];
	struct __cuckoo_hash_bucket padd2[65536];
};

// BPF map definitions
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct dummy_struct);
	__uint(pinning, 1);
#ifdef CUCKOO_HASH_MAP_SHARED
	__uint(map_flags, BPF_F_MMAPABLE);
#endif
} cuckoo_hash_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct __cuckoo_hash_bfs_queue);
	__uint(pinning, 1);
} __cuckoo_hash_bfs_queue_map SEC(".maps");
