#include "common.h"

/* Reuse code from cuckoo hash eBPF implementation */
#include "cuckoo_hash.c"

#include "cuckoo_hash_prefill.h"

SEC("xdp")
int prefill(struct xdp_md *ctx)
{
	struct cuckoo_hash_parameters params = {};
	struct cuckoo_hash *h;
	struct pkt_5tuple_with_pad pkt = { 0 };
	uint32_t i;
	uint16_t key_idx;

	h = get_cuckoo_hash(&params);
	if (unlikely(h == NULL)) {
		cuckoo_log(error, "cannot get cuckoo hash");
		return -EINVAL;
	}

	pkt.pkt.src_ip = CUCKOO_HASH_SRC_IP;
	pkt.pkt.src_port = CUCKOO_HASH_SRC_PORT;
	pkt.pkt.dst_ip = CUCKOO_HASH_DST_IP;
	pkt.pkt.proto = CUCKOO_HASH_PROTO;

	cuckoo_log(info, "prefilling primary bucket 0");
	for (i = 0; i < CUCKOO_HASH_BUCKET_ENTRIES; ++i) {
		pkt.pkt.dst_port = __cuckoo_hash_prim_bucket_ports[0][i];
		key_idx = i + 1;

		h->buckets[0].sig_current[i] = __cuckoo_hash_get_short_sig(
			__cuckoo_hash_hash(h, &pkt));
		h->buckets[0].key_idx[i] = key_idx;

		__builtin_memcpy(&h->key_store[key_idx].key, &pkt,
				 CUCKOO_HASH_KEY_SIZE);
		h->key_store[key_idx].value = 1;

		cuckoo_log(
			info,
			"prefilled port = 0x%04x in primary bucket 0, i = %d, key_idx = %d",
			pkt.pkt.dst_port, i, key_idx);
	}

	cuckoo_log(info, "prefilling secondary bucket 1");
	for (i = 0; i < CUCKOO_HASH_BUCKET_ENTRIES; ++i) {
		pkt.pkt.dst_port = __cuckoo_hash_sec_bucket_ports[1][i];
		key_idx = i + CUCKOO_HASH_BUCKET_ENTRIES + 1;

		h->buckets[1].sig_current[i] = __cuckoo_hash_get_short_sig(
			__cuckoo_hash_hash(h, &pkt));
		h->buckets[1].key_idx[i] = key_idx;

		__builtin_memcpy(&h->key_store[key_idx].key, &pkt,
				 CUCKOO_HASH_KEY_SIZE);
		h->key_store[key_idx].value = 1;

		cuckoo_log(
			info,
			"prefilled port = 0x%04x in sec bucket 1, i = %d, key_idx = %d",
			pkt.pkt.dst_port, i, key_idx);
	}

	cuckoo_log(info, "prefilling primary bucket 2");
	for (i = 0; i < CUCKOO_HASH_BUCKET_ENTRIES; ++i) {
		pkt.pkt.dst_port = __cuckoo_hash_prim_bucket_ports[2][i];
		key_idx = i + CUCKOO_HASH_BUCKET_ENTRIES * 2 + 1;

		h->buckets[2].sig_current[i] = __cuckoo_hash_get_short_sig(
			__cuckoo_hash_hash(h, &pkt));
		h->buckets[2].key_idx[i] = key_idx;

		__builtin_memcpy(&h->key_store[key_idx].key, &pkt,
				 CUCKOO_HASH_KEY_SIZE);
		h->key_store[key_idx].value = 1;

		cuckoo_log(
			info,
			"prefilled port = 0x%04x in primary bucket 2, i = %d, key_idx = %d",
			pkt.pkt.dst_port, i, key_idx);
	}

	cuckoo_log(info, "prefilling secondary bucket 3");
	for (i = 0; i < CUCKOO_HASH_BUCKET_ENTRIES; ++i) {
		pkt.pkt.dst_port = __cuckoo_hash_sec_bucket_ports[3][i];
		key_idx = i + CUCKOO_HASH_BUCKET_ENTRIES * 3 + 1;

		h->buckets[3].sig_current[i] = __cuckoo_hash_get_short_sig(
			__cuckoo_hash_hash(h, &pkt));
		h->buckets[3].key_idx[i] = key_idx;

		__builtin_memcpy(&h->key_store[key_idx].key, &pkt,
				 CUCKOO_HASH_KEY_SIZE);
		h->key_store[key_idx].value = 1;

		cuckoo_log(
			info,
			"prefilled port = 0x%04x in sec bucket 3, i = %d, key_idx = %d",
			pkt.pkt.dst_port, i, key_idx);
	}

	/*
	 * After the prefill, h->free_slot_list is in an invalid state, and
	 * inserting new keys will result in unexpected behavior.
	 */

	return 0;
}
