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

int main() {
        BPF_XDP_SKEL_LOADER(sched_time_wheel, "ens4np0", xdp_main, XDP_FLAGS_DRV_MODE)
}