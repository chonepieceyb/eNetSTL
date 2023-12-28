#include "../common.h" 
#include <stdio.h>
#include <assert.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "../bpf_skel/sched_scmap_time_wheel.skel.h"
#include <net/if.h>
#include <linux/if_link.h>

#include "../test_helpers.h"

void test1() {
        char buf[128];                  //store the output packet 
        LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.data_out = buf,
		.data_size_out = sizeof(buf),
		.repeat = 1,
	);

        struct sched_scmap_time_wheel * skel = NULL;
        struct bpf_program *prog;
        int res = 0;
        skel = sched_scmap_time_wheel__open();
        if (skel == NULL) {
                fprintf(stdout, "faild to open and load hw_demo\n");
                return; 
        }
        prog = skel->progs.test_timewheel;
        set_prog_flags_test(prog);

        res = sched_scmap_time_wheel__load(skel);
        if (CHECK_FAIL(res)) {
                goto clean;
        }
                
        res = bpf_prog_test_run_opts(bpf_program__fd(prog), &topts);
	//memcpy(&iph, buf + sizeof(struct ethhdr), sizeof(iph));
	ASSERT_OK(res, "test_run");
	ASSERT_EQ(topts.retval, XDP_PASS, "sucess");
clean:;
        sched_scmap_time_wheel__destroy(skel);
        return;
}

int main() {
        test1();
}