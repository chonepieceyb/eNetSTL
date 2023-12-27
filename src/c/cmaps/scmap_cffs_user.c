#include "../common.h" 
#include <stdio.h>
#include <assert.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "../bpf_skel/scmap_cFFS_PIQ.skel.h"
#include <net/if.h>
#include <linux/if_link.h>

#define IF_NAME "ens4np0"

int main() {
        struct scmap_cFFS_PIQ * skel = NULL;
        struct bpf_program *prog;
        int fd, ifindex, res;
        res = 0;
        ifindex = if_nametoindex(IF_NAME);
        if (ifindex == 0) {
                printf("failed to get ifindex %s\n", strerror(errno));
                return -1;
        }
        skel = scmap_cFFS_PIQ__open();
        if (skel == NULL) {
                printf("faild to open and load hw_demo\n");
                return -1; 
        }
        prog = skel->progs.xdp_main;
        res = scmap_cFFS_PIQ__load(skel);
        if (res) {
                printf("faild to load, res %d %s\n", res, strerror(errno));
                goto clean;
        }
                
        fd = bpf_program__fd(prog);
        
        //res = bpf_xdp_attach(index, fd, XDP_FLAGS_HW_MODE, NULL);
        res = bpf_xdp_attach(ifindex, fd, XDP_FLAGS_DRV_MODE, NULL);
        if (res < 0) {
                printf("failed to offload prog %d to nic %d, res: %d , %s\n", fd, ifindex, res, strerror(errno));
                goto clean;
        }
clean:;
        scmap_cFFS_PIQ__destroy(skel);
        return res;
}