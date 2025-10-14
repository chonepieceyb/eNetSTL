#include "../common.h"
#include "../config.h"
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <netinet/tcp.h>
#include <bpf/bpf_endian.h>
#include "../bpf_skel/test_static_ptr.skel.h"
#include "../test_helpers.h"
#include <unistd.h>

static void test_skiplist_init(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct test_static_ptr *skel;
	struct bpf_program *prog_init, *prog_lookup;
	int ret;

	skel = test_static_ptr__open();
	if (skel == NULL) {
		fprintf(stderr, "Failed to open test_ebpf_arena\n");
		return;
	}

	//Set program flags for testing
	prog_init = skel->progs.arena_skiplist_init;
	set_prog_flags_test(prog_init);
	prog_lookup = skel->progs.arena_skiplist_lookup;
	set_prog_flags_test(prog_lookup);

	ret = test_static_ptr__load(skel);
	if (CHECK_FAIL(ret)) {
		goto out;
	}

	/* RUN INIT */
	ret = bpf_prog_test_run_opts(bpf_program__fd(prog_init), &opts);
	ASSERT_OK(ret, "arena_skiplist_init test_run_opts");
	ASSERT_OK(opts.retval, "arena_skiplist_init retval");
	
	sleep(2);
	/* RUN LOOKUP */
	ret = bpf_prog_test_run_opts(bpf_program__fd(prog_lookup), &opts);
	ASSERT_OK(ret, "arena_skiplist_lookup test_run_opts");
	ASSERT_OK(opts.retval, "arena_skiplist_lookup retval");

out:
	test_static_ptr__destroy(skel);
}


int main(int argc, char **argv)
{
    test_skiplist_init();
    return 0;
}