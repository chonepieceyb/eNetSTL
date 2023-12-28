#include "../common.h" 
#include <stdio.h>
#include <assert.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "../bpf_skel/scmap_empty.skel.h"
#include <net/if.h>
#include <linux/if_link.h>

#define IF_NAME "ens4np0"

int main() {
        BPF_XDP_SKEL_LOADER(scmap_empty, "ens4np0", xdp_main, XDP_FLAGS_DRV_MODE)
}