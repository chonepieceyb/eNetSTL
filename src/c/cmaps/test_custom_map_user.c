#include "../common.h" 
#include "../bpf_skel/cmap_demo.skel.h"
#include "../test_helpers.h"

#define CMAP_ID 100

void test1() {
        char buf[128];                  //store the output packet 
        unsigned long id = CMAP_ID; 
        LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.data_out = buf,
		.data_size_out = sizeof(buf),
		.repeat = 1,
	);

        struct cmap_demo * skel = NULL;
        struct bpf_program *prog;
        int res = 0;
        skel = cmap_demo__open();
        if (skel == NULL) {
                fprintf(stdout, "faild to open and load hw_demo\n");
                return; 
        }

        res = bpf_map__set_map_extra(skel->maps.cmap, id << 32);
        if (res <0) {
                printf("faild to set cmap id\n");
                goto clean;
        }

        prog = skel->progs.xdp_main;
        set_prog_flags_test(prog);

        res = cmap_demo__load(skel);
        if (CHECK_FAIL(res)) {
                goto clean;
        }
                
        res = bpf_prog_test_run_opts(bpf_program__fd(prog), &topts);
	//memcpy(&iph, buf + sizeof(struct ethhdr), sizeof(iph));
	ASSERT_OK(res, "test_run");
	ASSERT_EQ(topts.retval, XDP_PASS, "sucess");

clean:;
        cmap_demo__destroy(skel);
        return;
}

int main() {
        test1();
}