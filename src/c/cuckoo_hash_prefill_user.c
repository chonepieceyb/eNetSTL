#include "common.h"
#include "test_helpers.h"

#include <bpf/libbpf.h>

#include "bpf_skel/cuckoo_hash_prefill.skel.h"

#define __USE_GNU
#include <sched.h>


#define set_test_cpu(skel)                                       \
	({                                                       \
		topts.cpu = cpu; /* FIXME: this does not work */ \
		0;                                               \
	})


static int empty_before_load(void *skel)
{
	return 0;
}

void __run_prefill_with_cpu(uint32_t cpu)
{
	BPF_PROG_TEST_RUNNER_WITH_CALLBACK("cuckoo_hash prefill",
					   cuckoo_hash_prefill, pkt_v4, prefill,
					   1, empty_before_load, set_test_cpu, 0);
}

int run_prefill_with_cpu(uint32_t cpu)
{
	__run_prefill_with_cpu(cpu);
	return 0;
}

void __run_prefill_with_cpu2(void)
{
	BPF_PROG_TEST_RUNNER("cuckoo_hash prefill", cuckoo_hash_prefill, pkt_v4,
			     prefill, 1, 0);
}

int run_prefill_with_cpu2(uint32_t cpu)
{
	int res = 0;
	cpu_set_t cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
	if ((res = sched_setaffinity(0, sizeof(cpuset), &cpuset)) != 0) {
		printf("Failed to set affinity: %d\n", res);
		return res;
	}

	__run_prefill_with_cpu2();

	return 0;
}

int main()
{
	int ncpus, res, ret = 0;

	if ((ncpus = libbpf_num_possible_cpus()) < 0) {
		printf("Failed to get number of CPUs\n");
		return 1;
	} else {
		printf("Got %d CPUs\n", ncpus);
	}

	for (int i = 0; i < ncpus; i++) {
		printf("Prefilling with CPU %d\n", i);
		if ((res = run_prefill_with_cpu2(i)) != 0) {
			printf("Failed to prefill with CPU %d: %d\n", i, res);
			ret++;
		}
	}

	printf("Prefill done\n");

	return ret;
}
