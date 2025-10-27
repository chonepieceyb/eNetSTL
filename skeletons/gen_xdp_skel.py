#!/usr/bin/env python3
"""
This script generates XDP skeleton code by inheriting from CommonSkeleton class.
Generates XDP program skeleton with user-space loader.
"""

from skels_common import CommonSkeleton


class XdpSkeleton(CommonSkeleton):
    """Generates XDP program skeleton code snippets."""

    def __init__(self, subproject: str = "", author_name: str = "", version: str = ""):
        super().__init__(subproject, author_name, version)

    def skel_bpf_prog_sec(self, **kwargs) -> str:
        """Generate XDP program implementation."""
        return """
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
"""

    def skel_user_c_header_sec(self, **kwargs) -> str:
        """Generate user program header section."""
        subproject = kwargs.get('subproject', self.subproject)
        return f"""#include "../common.h"
#include "../config.h"
#include "../bpf_skel/{subproject}.bpf.skel.h\""""

    def skel_user_c_impl_sec(self, **kwargs) -> str:
        """Generate user program implementation section."""
        return """static int callback_before_load(void *skel)
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
"""

    def skel_user_c_main_sec(self, **kwargs) -> str:
        """Generate user program main function section."""
        subproject = kwargs.get('subproject', self.subproject)
        return f"""int main() {{
    BPF_XDP_SKEL_LOADER_WITH_CALLBACKS({subproject}_bpf, XDP_IF, xdp_main,
		callback_before_load,
        callback_after_load,
		callback_after_attach,
		XDP_MODE)
}}
"""


if __name__ == "__main__":
    # Example usage
    skeleton = XdpSkeleton("example_subproject", "Author Name", "1.0.0")
    print("=== BPF Program Section ===")
    print(skeleton.skel_bpf_prog_sec())
    print("\n=== User C Header Section ===")
    print(skeleton.skel_user_c_header_sec())
    print("\n=== User C Implementation Section ===")
    print(skeleton.skel_user_c_impl_sec())
    print("\n=== User C Main Section ===")
    print(skeleton.skel_user_c_main_sec())