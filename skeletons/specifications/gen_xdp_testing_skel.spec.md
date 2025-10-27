TODO: this scripts generates code snippets by inheriting from CommonSkeleton class in skeleton

### skel_user_c_header_sec

param:
    subproject: name of the subproject, no default value
    
generate:

```c
#include "../common.h"
#include "../test_helpers.h"
#include "../config.h"
#include "../bpf_skel/$subproject.bpf.skel.h"
```

### skel_user_c_impl_sec


generate:

```c
static int callback_before_load(void *skel)
{
	/* you can clear pinned maps here for example */
	// remove("/sys/fs/bpf/nn_parameters");
    // remove("/sys/fs/bpf/nn_idx");
	return 0;
}


static int callback_after_run(void *skel, int run_result, int prog_retval)
{
    /* you can check results here */
	return 0;
}

static int callback_after_load(void *__skel)
{
	/* you can initialize maps here */
	return 0;
}

int test_xdp() {
	/* you can modiy the input packet of here, e.g., modify pkt_v4 */
	BPF_PROG_TEST_RUNNER_WITH_CALLBACK("test_$subproject", $subproject_bpf, pkt_v4, xdp_main, 1,
		callback_before_load,
		callback_after_load,
		callback_after_run, 
		XDP_PASS);
}

```

### skel_user_c_main_sec

param:
	no

generate:

```c
	int main() {
		return test_xdp();
	}
```