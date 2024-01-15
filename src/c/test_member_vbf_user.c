#include "common.h" 
#include <asm/ptrace.h>
#include <stdio.h>
#include <assert.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "bpf_skel/member_vbf.skel.h"
#include <net/if.h>
#include <linux/if_link.h>
#include <math.h>
#include <stdint.h>

#include "test_helpers.h"

#define NUM_KEYS 1000
#define NUM_SET 8
#define FALSE_POSITIVE_RATE 0.03

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

void vbf_test() {
	char buf[128];                  //store the output packet 
	LIBBPF_OPTS(bpf_test_run_opts, topts,
	.data_in = &pkt_v4,
	.data_size_in = sizeof(pkt_v4),
	.data_out = buf,
	.data_size_out = sizeof(buf),
	.repeat = 1,
	);

	struct member_vbf * skel = NULL;
	struct bpf_program *prog;
	int res = 0, prog_fd;
	skel = member_vbf__open();
	if (skel == NULL) {
		fprintf(stdout, "faild to open and load hw_demo\n");
		return; 
	}

	/* calculate the parmas */
	uint32_t num_keys_per_bf = 1 + (NUM_KEYS - 1) / NUM_SET;
	float fp_one_bf = 1 - pow((1 - FALSE_POSITIVE_RATE),
					1.0 / NUM_SET);
	uint32_t bits = ceil((num_keys_per_bf *
			log(fp_one_bf)) /
			log(1.0 / (pow(2.0, log(2.0)))));
	bits = align32pow2(bits);
	uint32_t num_hashes = (uint32_t)(log(2.0) * bits / num_keys_per_bf);
	uint32_t bit_mask = bits - 1;

	float new_fp = pow((1 - pow((1 - 1.0 / bits), num_keys_per_bf *
					num_hashes)), num_hashes);
	new_fp = 1 - pow((1 - new_fp), NUM_SET);

	int tmp_num_hash = num_hashes;

	while (tmp_num_hash > 1) {
		float tmp_fp = new_fp;

		tmp_num_hash--;
		new_fp = pow((1 - pow((1 - 1.0 / bits), num_keys_per_bf *
					tmp_num_hash)), tmp_num_hash);
		new_fp = 1 - pow((1 - new_fp), NUM_SET);

		if (new_fp > FALSE_POSITIVE_RATE) {
			new_fp = tmp_fp;
			tmp_num_hash++;
			break;
		}
	}

	num_hashes = tmp_num_hash;
	uint32_t mul_shift = ctz32(NUM_SET);
	uint32_t div_shift = ctz32(32 >> mul_shift);

	/* alter the args in eBPF program */
	// skel->bss->num_keys = NUM_KEYS;
	// skel->bss->num_set = NUM_SET;
	// skel->bss->num_keys_per_bf = num_keys_per_bf;
	// skel->bss->bits = bits;
	// skel->bss->num_hashes = num_hashes;
	// skel->bss->bit_mask = bit_mask;
	// skel->bss->mul_shift = mul_shift;
	// skel->bss->div_shift = div_shift;
	printf("num_keys: %u\n", NUM_KEYS);
	printf("num_set: %u\n", NUM_SET);
	printf("num_keys_per_bf: %u\n", num_keys_per_bf);
	printf("bits: %u\n", bits);
	printf("bit_mask: %u\n", bit_mask);
	printf("num_hashes: %u\n", num_hashes);
	printf("mul_shift: %u\n", mul_shift);
	printf("div_shift: %u\n", div_shift);


	prog = skel->progs.test_vbf;
	set_prog_flags_test(prog);
	res = member_vbf__load(skel);
	if (CHECK_FAIL(res)) {
		goto clean;
	}
					
	prog_fd = bpf_program__fd(prog);
	res = bpf_prog_test_run_opts(prog_fd, &topts);

clean:;
	member_vbf__destroy(skel);
	return;
}


int main() {
	vbf_test();
}