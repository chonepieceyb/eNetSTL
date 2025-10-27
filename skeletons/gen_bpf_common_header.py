#!/usr/bin/env python3
"""
This script generates code snippets by inheriting from CommonSkeleton class.
Generates common BPF header sections.
"""

from skels_common import CommonSkeleton


class BpfCommonHeaderSkeleton(CommonSkeleton):
    """Generates common BPF header code snippets."""

    def skel_bpf_header_sec(self, **kwargs) -> str:
        """Generate shared code snippet for BPF program header section."""
        return """#include "../common.h"

/* for statistics */
char _license[] SEC("license") = "GPL";
PACKET_COUNT_MAP_DEFINE"""


if __name__ == "__main__":
    # Example usage
    skeleton = BpfCommonHeaderSkeleton()
    print(skeleton.skel_bpf_header_sec())