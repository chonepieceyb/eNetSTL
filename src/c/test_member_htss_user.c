#include "common.h" 
#include <asm/ptrace.h>
#include <stdio.h>
#include <assert.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "bpf_skel/member_htss.skel.h"
#include <net/if.h>
#include <linux/if_link.h>
#include <math.h>
#include <stdint.h>

#include "test_helpers.h"


#define NUM_KEYS 3
/* Entry count per bucket in hash table based mode. */
#define MEMBER_BUCKET_ENTRIES 2

/**
 * Combines 32b inputs most significant set bits into the least
 * significant bits to construct a value with the same MSBs as x
 * but all 1's under it.
 *
 * @param x
 *    The integer whose MSBs need to be combined with its LSBs
 * @return
 *    The combined value.
 */
static inline uint32_t
combine32ms1b(uint32_t x)
{
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;

	return x;
}

/**
 * Aligns input parameter to the next power of 2
 *
 * @param x
 *   The integer value to align
 *
 * @return
 *   Input parameter aligned to the next power of 2
 */
static inline uint32_t
align32pow2(uint32_t x)
{
	x--;
	x = combine32ms1b(x);

	return x + 1;
}

/**
 * Get the count of trailing 0-bits in v.
 *
 * @param v
 *   The value.
 * @return
 *   The count of trailing zero bits.
 */
static inline unsigned int
ctz32(uint32_t v)
{
	return (unsigned int)__builtin_ctz(v);
}

void htss_test() {
	char buf[128];                  //store the output packet 
	LIBBPF_OPTS(bpf_test_run_opts, topts,
	.data_in = &pkt_v4,
	.data_size_in = sizeof(pkt_v4),
	.data_out = buf,
	.data_size_out = sizeof(buf),
	.repeat = 1,
	);

	struct member_htss * skel = NULL;
	struct bpf_program *prog;
	int res = 0, prog_fd;
	skel = member_htss__open();
	if (skel == NULL) {
		fprintf(stdout, "faild to open and load hw_demo\n");
		return; 
	}

	/* calculate the parmas */
	uint32_t num_keys = NUM_KEYS;
	uint32_t num_entries = align32pow2(num_keys);
	uint32_t num_buckets = num_entries / MEMBER_BUCKET_ENTRIES;
	uint32_t size_bucket_t = sizeof(uint32_t);
	uint32_t bucket_mask = num_buckets - 1;


	/* alter the args in eBPF program */
	// skel->bss->num_keys = NUM_KEYS;

	/* get params */
	printf("num_keys: %u\n", NUM_KEYS);
	printf("num_entries: %u\n", num_entries);
	printf("num_buckets: %u\n", num_buckets);
	printf("size_bucket_t: %u\n", size_bucket_t);
	printf("bucket_mask: %u\n", bucket_mask);

	prog = skel->progs.test_htss;
	set_prog_flags_test(prog);
	res = member_htss__load(skel);
	if (CHECK_FAIL(res)) {
		goto clean;
	}
					
	prog_fd = bpf_program__fd(prog);
	res = bpf_prog_test_run_opts(prog_fd, &topts);

clean:;
	member_htss__destroy(skel);
	return;
}


int main() {
	htss_test();
}