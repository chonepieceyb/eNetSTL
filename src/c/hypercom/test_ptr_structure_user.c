#include "../common.h" 
#include "../bpf_skel/ptr_structure_test.skel.h"
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
	struct ptr_structure_test * skel = NULL;				
	struct bpf_program *prog1, *prog2, *prog3;						
	int res = 0, prog_fd;						
	skel = ptr_structure_test__open();						
	if (skel == NULL) {								
		fprintf(stdout, "faild to open and load ptr_structure_test\n");			
		return; 									
	}											
	prog1 = skel->progs.test_structure_ptr_write;		
        prog2 = skel->progs.test_structure_op;		
        prog3 = skel->progs.test_structure_read;							
	set_prog_flags_test(prog1);
        set_prog_flags_test(prog2);		
        set_prog_flags_test(prog3);							
	res = ptr_structure_test__load(skel);							
	if (CHECK_FAIL(res)) {									
		goto clean;									
	}											
	res = bpf_prog_test_run_opts(bpf_program__fd(prog1), &topts);				
	ASSERT_OK(res, "bpf_prog_test_run_opts res");						
	ASSERT_EQ(topts.retval, XDP_PASS, "test_structure_read");
        res = bpf_prog_test_run_opts(bpf_program__fd(prog2), &topts);				
	ASSERT_OK(res, "bpf_prog_test_run_opts res");						
	ASSERT_EQ(topts.retval, XDP_PASS, "test_structure_op");
        res = bpf_prog_test_run_opts(bpf_program__fd(prog3), &topts);				
	ASSERT_OK(res, "bpf_prog_test_run_opts res");						
	ASSERT_EQ(topts.retval, XDP_PASS,"test_structure_ptr_write");					
clean:;												
	ptr_structure_test__destroy(skel);								\
	return; 
}

int main() {
        test();
}