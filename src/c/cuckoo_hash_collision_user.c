#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include "crc.h"

#define CUCKOO_HASH_ENTRIES 512
#define CUCKOO_HASH_BUCKET_ENTRIES 16
#define CUCKOO_HASH_SEED 0xdeadbeef

#define CUCKOO_HASH_NUM_BUCKETS \
	(CUCKOO_HASH_ENTRIES / CUCKOO_HASH_BUCKET_ENTRIES)
#define CUCKOO_HASH_BUCKET_BITMASK (CUCKOO_HASH_NUM_BUCKETS - 1)

#define log(fmt, ...) \
	fprintf(stderr, "cuckoo_hash_collision_user: " fmt, ##__VA_ARGS__)

struct __cuckoo_hash_table {
	uint16_t ports[CUCKOO_HASH_BUCKET_ENTRIES];
	uint32_t size;
};

struct pkt_5tuple_with_pad {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t proto;
	uint8_t pad[3];
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

void __compute_collisions(struct pkt_5tuple_with_pad pkt, uint16_t port_start,
			  uint16_t port_end,
			  uint32_t (*get_index)(const uint32_t hash),
			  struct __cuckoo_hash_table *table)
{
	volatile uint32_t i; /* to avoid inappropriate compiler optimization */
	uint32_t hash, bkt_idx;

	for (i = port_start; i < port_end; ++i) {
		pkt.dst_port = i;
		hash = __cuckoo_hash_hash(&pkt, sizeof(pkt));
		bkt_idx = get_index(hash);
		if (table[bkt_idx].size >= CUCKOO_HASH_BUCKET_ENTRIES) {
			continue;
		}
		table[bkt_idx].ports[table[bkt_idx].size++] = i;
	}
}

void __print_ports(FILE *file, const char *name,
		   const struct __cuckoo_hash_table *table)
{
	uint32_t i;

	fprintf(file,
		"\nstatic const uint16_t %s[CUCKOO_HASH_EXPECTED_NUM_BUCKETS][CUCKOO_HASH_NUM_BUCKET_PORTS] = {\n",
		name);
	for (i = 0; i < CUCKOO_HASH_NUM_BUCKETS; ++i) {
		fprintf(file, "\t[%d] = {", i);
		for (int j = 0; j < table[i].size; ++j) {
			fprintf(file, "0x%04x, ", table[i].ports[j]);
		}
		fprintf(file, "},\n");
	}
	fprintf(file, "};\n");
}

void __print_prefill_header(FILE *file,
			    const struct __cuckoo_hash_table *prim_table,
			    const struct __cuckoo_hash_table *sec_table,
			    const struct pkt_5tuple_with_pad *pkt)
{
	fprintf(file,
		"#ifndef _CUCKOO_HASH_PREFILL_H\n"
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
		CUCKOO_HASH_NUM_BUCKETS, CUCKOO_HASH_BUCKET_ENTRIES,
		pkt->src_ip, pkt->dst_ip, pkt->src_port, pkt->proto);

	__print_ports(file, "__cuckoo_hash_prim_bucket_ports", prim_table);
	__print_ports(file, "__cuckoo_hash_sec_bucket_ports", sec_table);

	fprintf(file, "\n#endif\n");
}

int __write_traces(const struct pkt_5tuple_with_pad *pkt, const char *dir_path,
		   const struct __cuckoo_hash_table *prim_table,
		   const struct __cuckoo_hash_table *sec_table)
{
	for (int i = 0; i < CUCKOO_HASH_BUCKET_ENTRIES; ++i) {
		char trace_path[256];
		snprintf(trace_path, sizeof(trace_path), "%s/compare_%d_trace",
			 dir_path, i);
		FILE *trace_file = fopen(trace_path, "w");
		if (!trace_file) {
			log("failed to open trace file %s\n", trace_path);
			return 1;
		}

		for (int j = 0; j < 100; ++j) {
			/*
			 * Byte order is not converted when parsing packet 5-tuples in the
			 * test code, so we need to convert it here.
			 */
			uint16_t dst_port1 = ntohs(prim_table[0].ports[i]);
			uint16_t dst_port2 = ntohs(prim_table[2].ports[i]);
			fprintf(trace_file,
				"%u\t%u\t%u\t%u\t%u\t512\t1\n%u\t%u\t%u\t%u\t%u\t512\t1\n",
				pkt->src_ip, pkt->dst_ip, pkt->src_port,
				dst_port1, pkt->proto, pkt->src_ip, pkt->dst_ip,
				pkt->src_port, dst_port2, pkt->proto);
		}

		fclose(trace_file);
		log("trace file %s written\n", trace_path);
	}

	return 0;
}

int __write_header(const struct pkt_5tuple_with_pad *pkt, const char *path,
		   const struct __cuckoo_hash_table *prim_table,
		   const struct __cuckoo_hash_table *sec_table)
{
	FILE *prefill_header_file = fopen(path, "w");
	if (!prefill_header_file) {
		log("failed to open prefill header file %s\n", path);
		return 1;
	}

	__print_prefill_header(prefill_header_file, prim_table, sec_table, pkt);
	fclose(prefill_header_file);
	log("prefill header file %s written\n", path);

	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 3) {
		log("usage: %s <trace_directory> <prefill_header>\n", argv[0]);
		return 1;
	}

	struct pkt_5tuple_with_pad pkt = {
		.src_ip = 0x01020201,
		.dst_ip = 0x03040403,
		.src_port = 0x0505,
		.dst_port = 0,
		.proto = 6,
		.pad = { 0 },
	};
	struct __cuckoo_hash_table prim_table[CUCKOO_HASH_NUM_BUCKETS],
		sec_table[CUCKOO_HASH_NUM_BUCKETS];

	memset(prim_table, 0, sizeof(prim_table));
	memset(sec_table, 0, sizeof(sec_table));

	__compute_collisions(pkt, 1, 32768, __cuckoo_hash_get_prim_bucket_index,
			     prim_table);
	__compute_collisions(pkt, 32768, 65535,
			     __cuckoo_hash_get_sec_bucket_index, sec_table);

	__write_traces(&pkt, argv[1], prim_table, sec_table);

	__write_header(&pkt, argv[2], prim_table, sec_table);

	return 0;
}
