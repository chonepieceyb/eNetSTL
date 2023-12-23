#include "common.h" 
#include <stdio.h>
#include <assert.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "bpf_skel/sched_time_wheel.skel.h"
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

        struct sched_time_wheel * skel = NULL;
        struct bpf_program *prog;
        int res = 0, prog_fd;
        skel = sched_time_wheel__open();
        if (skel == NULL) {
                fprintf(stdout, "faild to open and load hw_demo\n");
                return; 
        }
        prog = skel->progs.map_list_push_pop;
        set_prog_flags_test(prog);
        res = sched_time_wheel__load(skel);
        if (CHECK_FAIL(res)) {
                goto clean;
        }
                
        prog_fd = bpf_program__fd(prog);
        res = bpf_prog_test_run_opts(prog_fd, &topts);
	//memcpy(&iph, buf + sizeof(struct ethhdr), sizeof(iph));
	ASSERT_OK(res, "test_run");
	ASSERT_EQ(topts.retval, 0, "sucess");

clean:;
        sched_time_wheel__destroy(skel);
        return;
}

int main() {
        test1();
}