#!/usr/bin/env python3
"""
This script generates XDP testing skeleton code by inheriting from CommonSkeleton class.
Generates XDP program testing framework.
"""

from skels_common import CommonSkeleton


class XdpTestingSkeleton(CommonSkeleton):
    """Generates XDP testing program skeleton code snippets."""

    def __init__(self, subproject: str = "", author_name: str = "", version: str = ""):
        super().__init__(subproject, author_name, version)

    def skel_user_c_header_sec(self, **kwargs) -> str:
        """Generate user testing program header section."""
        subproject = kwargs.get('subproject', self.subproject)
        return f"""#include "../common.h"
#include "../test_helpers.h"
#include "../config.h"
#include "../bpf_skel/{subproject}.bpf.skel.h\""""

    def skel_user_c_impl_sec(self, **kwargs) -> str:
        """Generate user testing program implementation section."""
        subproject = kwargs.get('subproject', self.subproject)
        return f"""static int callback_before_load(void *skel)
{{
	/* you can clear pinned maps here for example */
	// remove("/sys/fs/bpf/nn_parameters");
    // remove("/sys/fs/bpf/nn_idx");
	return 0;
}}


static int callback_after_run(void *skel, int run_result, int prog_retval)
{{
    /* you can check results here */
	return 0;
}}

static int callback_after_load(void *__skel)
{{
	/* you can initialize maps here */
	return 0;
}}

int test_xdp() {{
	/* you can modify the input packet here, e.g., modify pkt_v4 */
	BPF_PROG_TEST_RUNNER_WITH_CALLBACK("test_{subproject}", {subproject}_bpf, pkt_v4, xdp_main, 1,
		callback_before_load,
		callback_after_load,
		callback_after_run,
		XDP_PASS);
}}"""

    def skel_user_c_main_sec(self, **kwargs) -> str:
        """Generate user testing program main function section."""
        return """int main() {
		return test_xdp();
	}"""


if __name__ == "__main__":
    # Example usage
    skeleton = XdpTestingSkeleton("example_subproject", "Author Name", "1.0.0")
    print("=== User C Header Section ===")
    print(skeleton.skel_user_c_header_sec())
    print("\n=== User C Implementation Section ===")
    print(skeleton.skel_user_c_impl_sec())
    print("\n=== User C Main Section ===")
    print(skeleton.skel_user_c_main_sec())