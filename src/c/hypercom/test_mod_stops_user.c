#include "../common.h" 
#include "../bpf_skel/mod_st_demo_base.skel.h"
#include "../bpf_skel/mod_st_demo_ext.skel.h"
#include "../test_helpers.h"

struct mod_st_demo_ext *load_st_ops(void)
{
        BPF_MOD_LOAD_STRUCT_OPS(mod_st_demo_ext, test_st_op, "mod_struct_ops_demo");
}

void test_run() {
        BPF_PROG_TEST_RUNNER("test mod st demo", mod_st_demo_base, pkt_v4, xdp_main, 1,  0);
}

void test() {
        struct mod_st_demo_ext *skel;
        skel = load_st_ops();
        if (skel == NULL)
                return;
        test_run();
        int key = 0;
        bpf_map__delete_elem(skel->maps.test_st_op, &key, sizeof(key), 0);
        mod_st_demo_ext__destroy(skel);
}

int main() {
        test();
}