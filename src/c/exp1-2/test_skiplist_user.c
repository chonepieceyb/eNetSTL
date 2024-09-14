#include "../common.h" 
#include "../bpf_skel/ptr_skiplist.skel.h"
#include "../test_helpers.h"


void test() {
       char buf[128];                  				
        LIBBPF_OPTS(bpf_test_run_opts, topts,			
		.data_in = &pkt_v4,							
		.data_size_in = sizeof(pkt_v4),				
		.data_out = buf,							
		.data_size_out = sizeof(buf),				
		.repeat = 1,							
	);												
	struct ptr_skiplist * skel = NULL;				
	struct bpf_program *prog1, *prog2, *prog3, *prog4;						
	int res = 0, prog_fd;						
	skel = ptr_skiplist__open();						
	if (skel == NULL) {								
		fprintf(stdout, "faild to open and load ptr_structure_test\n");			
		return; 									
	}											
	prog1 = skel->progs.test_skip_list1;	
        prog2 = skel->progs.test_skip_list2;		
        prog3 = skel->progs.xdp_main_lookup;
	prog4 = skel->progs.xdp_main_lookup_lite;						
	set_prog_flags_test(prog1);
        set_prog_flags_test(prog2);	
        set_prog_flags_test(prog3);		
	set_prog_flags_test(prog4);						
	res = ptr_skiplist__load(skel);							
	if (CHECK_FAIL(res)) {									
		goto clean;									
	}											
	res = bpf_prog_test_run_opts(bpf_program__fd(prog1), &topts);				
	ASSERT_OK(res, "bpf_prog_test_run_opts res");						
	ASSERT_EQ(topts.retval, XDP_PASS, "test1");
        res = bpf_prog_test_run_opts(bpf_program__fd(prog2), &topts);				
	ASSERT_OK(res, "bpf_prog_test_run_opts res");						
	ASSERT_EQ(topts.retval, XDP_PASS, "test2");	
        // res = bpf_prog_test_run_opts(bpf_program__fd(prog3), &topts);				
	// ASSERT_OK(res, "bpf_prog_test_run_opts res");
	// ASSERT_EQ(topts.retval, XDP_PASS, "test_lookup");	
	res = bpf_prog_test_run_opts(bpf_program__fd(prog4), &topts);				
	ASSERT_OK(res, "bpf_prog_test_run_opts res");					
	ASSERT_EQ(topts.retval, XDP_PASS, "test_lookup_lite");			
clean:;												
	ptr_skiplist__destroy(skel);								\
	return; 
}

int main() {
        test();
}