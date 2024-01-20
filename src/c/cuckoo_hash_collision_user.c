#include <stdio.h>
#include <stdint.h>

#include "../bpf_kern/crc.h"
#include <string.h>

#define CUCKOO_HASH_ENTRIES 512
#define CUCKOO_HASH_BUCKET_ENTRIES 16
#define CUCKOO_HASH_SEED 0xdeadbeef

#define CUCKOO_HASH_NUM_BUCKETS \
	(CUCKOO_HASH_ENTRIES / CUCKOO_HASH_BUCKET_ENTRIES)
#define CUCKOO_HASH_BUCKET_BITMASK (CUCKOO_HASH_NUM_BUCKETS - 1)

#define log(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)

struct __cuckoo_hash_table {
	uint16_t ports[CUCKOO_HASH_BUCKET_ENTRIES];
	uint32_t size;
};

struct pkt_5tuple {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t proto;
} __attribute__((packed));

static uint32_t __cuckoo_hash_hash(const void *data, size_t len)
{
	return crc32c(data, len, CUCKOO_HASH_SEED);
}

static uint16_t __cuckoo_hash_get_short_sig(const uint32_t hash)
{
	return hash >> 16;
}

static uint32_t __cuckoo_hash_get_prim_bucket_index(const uint32_t hash)
{
	return hash & CUCKOO_HASH_BUCKET_BITMASK;
}

static uint32_t __cuckoo_hash_get_alt_bucket_index(uint32_t cur_bkt_idx,
						   uint16_t sig)
{
	return (cur_bkt_idx ^ sig) & CUCKOO_HASH_BUCKET_BITMASK;
}

static uint32_t __cuckoo_hash_get_sec_bucket_index(const uint32_t hash)
{
	uint16_t short_sig = __cuckoo_hash_get_short_sig(hash);
	uint32_t prim_bkt_idx = __cuckoo_hash_get_prim_bucket_index(hash);
	return __cuckoo_hash_get_alt_bucket_index(prim_bkt_idx, short_sig);
}

void __compute_collisions(struct pkt_5tuple pkt, uint16_t port_start,
			  uint16_t port_end,
			  uint32_t (*get_index)(const uint32_t hash),
			  const char *name)
{
	struct __cuckoo_hash_table ports_by_bucket[CUCKOO_HASH_NUM_BUCKETS];
	uint32_t i, hash, bkt_idx;
	memset(ports_by_bucket, 0, sizeof(ports_by_bucket));

	for (i = port_start; i < port_end; ++i) {
		pkt.src_port = i;
		hash = __cuckoo_hash_hash(&pkt, sizeof(pkt));
		bkt_idx = get_index(hash);
		if (ports_by_bucket[bkt_idx].size >=
		    CUCKOO_HASH_BUCKET_ENTRIES) {
			log("%s: %u: ports full for bucket %u\n", name, i,
			    bkt_idx);
			continue;
		}
		ports_by_bucket[bkt_idx].ports[ports_by_bucket[bkt_idx].size++] =
			i;
	}

	printf("\nstatic const uint16_t %s[CUCKOO_HASH_EXPECTED_NUM_BUCKETS][CUCKOO_HASH_NUM_BUCKET_PORTS] = {\n",
	       name);
	for (i = 0; i < CUCKOO_HASH_NUM_BUCKETS; ++i) {
		printf("\t[%d] = {", i);
		for (int j = 0; j < ports_by_bucket[i].size; ++j) {
			printf("0x%04x, ", ports_by_bucket[i].ports[j]);
		}
		printf("},\n");
	}
	printf("};\n");
}

int main()
{
	struct pkt_5tuple pkt = {
		.src_ip = 0x01020201,
		.dst_ip = 0x03040403,
		.src_port = 0x0505,
		.dst_port = 0,
		.proto = 6,
	};

	printf("#ifndef _CUCKOO_HASH_PREFILL_H\n"
	       "#define _CUCKOO_HASH_PREFILL_H\n"
	       "\n"
	       "#define CUCKOO_HASH_EXPECTED_NUM_BUCKETS %d\n"
	       "#if CUCKOO_HASH_EXPECTED_NUM_BUCKETS != CUCKOO_HASH_NUM_BUCKETS\n"
	       "#error calculated data does not match CUCKOO_HASH_NUM_BUCKETS\n"
	       "#endif\n"
	       "\n"
	       "#define CUCKOO_HASH_NUM_BUCKET_PORTS %d\n"
	       "#if CUCKOO_HASH_BUCKET_ENTRIES > CUCKOO_HASH_NUM_BUCKET_PORTS\n"
	       "#error calculated ports are not enough\n"
	       "#endif\n"
	       "\n"
	       "#define CUCKOO_HASH_SRC_IP 0x%08x\n"
	       "#define CUCKOO_HASH_DST_IP 0x%08x\n"
	       "#define CUCKOO_HASH_SRC_PORT 0x%04x\n"
	       "#define CUCKOO_HASH_PROTO 0x%02x\n",
	       CUCKOO_HASH_NUM_BUCKETS, CUCKOO_HASH_BUCKET_ENTRIES, pkt.src_ip,
	       pkt.dst_ip, pkt.src_port, pkt.proto);

	__compute_collisions(pkt, 1, 32768, __cuckoo_hash_get_prim_bucket_index,
			     "__cuckoo_hash_prim_bucket_ports");
	__compute_collisions(pkt, 32768, 65535,
			     __cuckoo_hash_get_sec_bucket_index,
			     "__cuckoo_hash_sec_bucket_ports");

	printf("\n#endif\n");

	return 0;
}
