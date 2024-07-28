#include <linux/module.h>
extern int rust_func(const char *str);   // defined in rust

static int bpf_enetstl_init(void)
{
    int res = rust_func("C module say hello to RUST");
    pr_info("loading bpf enesetl %d\n", res);
    return 0;
}

static void bpf_enetstl_exit(void)
{
    return;
}

module_init(bpf_enetstl_init);
module_exit(bpf_enetstl_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chonepieceyb");
MODULE_DESCRIPTION("BPF networking datapath base ALG kfunc sets");
MODULE_VERSION("0.01");