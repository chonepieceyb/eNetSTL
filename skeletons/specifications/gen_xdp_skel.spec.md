TODO: this scripts generates code snippets by inheriting from CommonSkeleton class in skeleton

### for skel_bpf_impl_sec
parms:
    none
generate: 

```c

/* lookup program */
SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	LATENCY_START_TIMESTAMP_DEFINE

	/* write your xdp code here */
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

	PACKET_COUNT_MAP_UPDATE

/* success */
#ifdef LATENCY_EXP
	SWAP_MAC_AND_RETURN_XDP_TX(ctx)
#endif
	return XDP_PASS;

error:;
/* error */
    return XDP_DROP;
}

```

### for skel_user_c_header_sec

param:
	subproject: name of the subproject, no default value

### skel_user_c_header_sec

param:
    subproject: name of the subproject, no default value
    
generate:

```c
#include "../common.h"
#include "../config.h"
#include "../bpf_skel/$subproject.bpf.skel.h"
```


### for skel_user_c_impl_sec

param:
	subproject: name of the subproject, no default value

generate:

```c

static int callback_before_load(void *skel)
{
	/* you can clear pinned maps here for example */
	// remove("/sys/fs/bpf/nn_parameters");
    // remove("/sys/fs/bpf/nn_idx");
	// remove("/sys/fs/bpf/progs");
	return 0;
}

static int callback_after_attach(void *skel)
{
	/* you can perform actions after attaching programs here */
	return 0;
}

static int callback_after_load(void *__skel)
{
	/* you can initialize maps here */
	return 0;
}
```

### skel_user_c_main_sec

param:
	subproject: name of the subproject, no default value

generate: 

```c
int main() {
    BPF_XDP_SKEL_LOADER_WITH_CALLBACKS($subproject_bpf, XDP_IF, xdp_main, 
		callback_before_load,
        callback_after_load,
		callback_after_attach, 
		XDP_MODE)
}

```