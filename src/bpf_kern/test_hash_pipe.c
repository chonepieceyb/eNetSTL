#include "common.h"

#include "vmlinux.h"
#include "xxhash.h"

#define hp_log(level, fmt, ...)                                  \
	log_##level(" hash_pipe (ebpf): " fmt " (%s @ line %d)", \
		    ##__VA_ARGS__, __func__, __LINE__)

#define hp_swap(a, b)                  \
	({                             \
		typeof(a) __tmp = (a); \
		(a) = (b);             \
		(b) = __tmp;           \
	})

// #define HP_EMPTY_HASH

#define D 8
#define M (128 * 1024 / 128 / 8)

#define SEED_BASE 0xdeadbeef

#define inline inline __attribute__((always_inline))

typedef struct pkt_5tuple hash_pipe_key_t;

struct hash_pipe_table {
	hash_pipe_key_t key[D][M];
	uint32_t val[D][M];
};

static inline uint32_t hash_pipe_hash(void *key, size_t len, uint32_t seed)
{
#ifdef HP_EMPTY_HASH
	return *(uint32_t *)key ^ seed;
#else
	return xxh32(key, len, seed);
#endif
}

static inline int hash_pipe_cmp(void *key1, void *key2, size_t len)
{
	return __builtin_memcmp(key1, key2, len);
}

static inline void hash_pipe_work(struct hash_pipe_table *table,
				  hash_pipe_key_t *key, uint32_t val)
{
	uint32_t i, l;

	for (i = 0; i < D; i++) {
		l = hash_pipe_hash(key, sizeof(*key), SEED_BASE + i) % M;

		if (hash_pipe_cmp(key, &table->key[i][l], sizeof(*key)) == 0) {
			l ^= 0x01; /* to avoid hash_pipe_cmp from being optimized out */
		}

		if (!table->val[i][l]) {
			l ^= 0x01; /* to avoid this block from being optimized out */
		}

		if (table->val[i][l] < val) {
			l ^= 0x01; /* to avoid this block from being optimized out */
		}

		hp_swap(table->key[i][l], *key);
		hp_swap(table->val[i][l], val);
	}
}

static inline void hash_pipe_insert(struct hash_pipe_table *table,
				    hash_pipe_key_t *key)
{
	uint32_t hash, l;

	hash = hash_pipe_hash(key, sizeof(*key), SEED_BASE);
	l = hash % M;

	if (hash_pipe_cmp(key, &table->key[0][l], sizeof(*key)) == 0) {
		l ^= 0x01; /* to avoid hash_pipe_cmp from being optimized out */
	}

	if (!table->val[0][l]) {
		l ^= 0x01; /* to avoid this block from being optimized out */
	}

	hash_pipe_work(table, &table->key[0][l], table->val[0][l]);

	__builtin_memcpy(&table->key[0][l], key, sizeof(*key));
	table->val[0][l] = 1;
}

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct hash_pipe_table);
} hash_pipe_table_map SEC(".maps");

char _license[] SEC("license") = "GPL";

SEC("xdp") int xdp_test_hash_pipe(struct xdp_md *ctx)
{
	struct pkt_5tuple key = { 0 };
	struct hdr_cursor nh = { .pos = (void *)(long)ctx->data };
	void *data_end = (void *)(long)ctx->data_end;
	int ret, zero = 0;
	struct hash_pipe_table *table;

	if ((ret = parse_pkt_5tuple(&nh, data_end, &key))) {
		hp_log(error, "failed to parse packet: %d", ret);
		goto out;
	} else {
		hp_log(debug,
		       "pkt: src_ip = 0x%08x, dst_ip = 0x%08x, "
		       "src_port = 0x%04x, dst_port = 0x%04x, proto = 0x%02x",
		       key.src_ip, key.dst_ip, key.src_port, key.dst_port,
		       key.proto);
	}

	if (!(table = bpf_map_lookup_elem(&hash_pipe_table_map, &zero))) {
		hp_log(error, "failed to lookup hash pipe table");
		goto out;
	}

	hash_pipe_insert(table, &key);
	hp_log(debug, "inserted");

out:
	return XDP_DROP;
}
