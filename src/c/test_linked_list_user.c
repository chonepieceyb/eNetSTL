#include "common.h" 
#include <stdio.h>
#include <assert.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "bpf_skel/linked_list_test.skel.h"
#include <net/if.h>
#include <linux/if_link.h>

#include "test_helpers.h"

void test1() {
        char buf[128];                  //store the output packet 
        LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.data_out = buf,
		.data_size_out = sizeof(buf),
		.repeat = 1,
	);

        struct linked_list_test * skel = NULL;
        struct bpf_program *prog, *prog2;
        int res = 0;
        skel = linked_list_test__open();
        if (skel == NULL) {
                fprintf(stdout, "faild to open and load hw_demo\n");
                return; 
        }
        prog = skel->progs.map_list_push_pop_inmap;
        prog2 = skel->progs.map_list_push_pop_global;
        set_prog_flags_test(prog);
        set_prog_flags_test(prog2);

        res = linked_list_test__load(skel);
        if (CHECK_FAIL(res)) {
                goto clean;
        }
                
        res = bpf_prog_test_run_opts(bpf_program__fd(prog), &topts);
	//memcpy(&iph, buf + sizeof(struct ethhdr), sizeof(iph));
	ASSERT_OK(res, "test_run1");
	ASSERT_EQ(topts.retval, 0, "sucess1");

        res = bpf_prog_test_run_opts(bpf_program__fd(prog2), &topts);
	//memcpy(&iph, buf + sizeof(struct ethhdr), sizeof(iph));
	ASSERT_OK(res, "test_run2");
	ASSERT_EQ(topts.retval, 0, "sucess2");

clean:;
        linked_list_test__destroy(skel);
        return;
}

int main() {
        test1();
}