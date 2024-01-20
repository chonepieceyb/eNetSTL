#include "common.h"
#include "test_helpers.h"

#include <bpf/libbpf.h>

#include "bpf_skel/cuckoo_hash_prefill.skel.h"

#define set_test_cpu(skel)       \
	({                       \
		topts.cpu = cpu; \
		0;               \
	})

void run_prefill_with_cpu(uint32_t cpu)
{
	BPF_PROG_TEST_RUNNER_WITH_CALLBACK("cuckoo_hash prefill",
					   cuckoo_hash_prefill, pkt_v4, prefill,
					   1, set_test_cpu, 0);
}

int main()
{
	int ncpus;

	if ((ncpus = libbpf_num_possible_cpus()) < 0) {
		printf("Failed to get number of cpus\n");
		return 1;
	} else {
		printf("Got %d cpus\n", ncpus);
	}

	for (int i = 0; i < ncpus; i++) {
		printf("Prefilling with CPU %d\n", i);
		run_prefill_with_cpu(i);
	}

	printf("Prefill done\n");

	return 0;
}
