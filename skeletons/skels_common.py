
"""
Common skeleton file is an abstraction for all skeleton generation scripts.

Comments with:
1. shared means that multiple types of Skeletons will generate code snippets for these sections,
   should merge them into common code snippet, for example common headers
2. exclusive means that only one type of Skeleton will generate code snippets in one file.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional


class CommonSkeleton(ABC):
    """Abstract base class for all skeleton generators."""

    def __init__(self, subproject: str = "", author_name: str = "", version: str = ""):
        self.subproject = subproject
        self.author_name = author_name
        self.version = version

    def skel_bpf_header_sec(self, **kwargs) -> str:
        """Generate shared code snippet for BPF program header section."""
        return """#include "../common.h"

/* for statistics */
char _license[] SEC("license") = "GPL";
PACKET_COUNT_MAP_DEFINE"""

    def skel_bpf_prog_sec(self, **kwargs) -> str:
        """Generate shared code snippet for a specific BPF program type."""
        return ""

    def skel_user_c_header_sec(self, **kwargs) -> str:
        """Generate shared code snippet for user program header section."""
        subproject = kwargs.get('subproject', self.subproject)
        return f"""#include "../common.h"
#include "../config.h"
#include "../bpf_skel/{subproject}.bpf.skel.h"""

    def skel_user_c_impl_sec(self, **kwargs) -> str:
        """Generate shared code snippet for function implementation in user program."""
        return """static int callback_before_load(void *skel)
{{
	/* you can clear pinned maps here for example */
	// remove("/sys/fs/bpf/nn_parameters");
    // remove("/sys/fs/bpf/nn_idx");
	// remove("/sys/fs/bpf/progs");
	return 0;
}

static int callback_after_attach(void *skel)
{{
	/* you can perform actions after attaching programs here */
	return 0;
}}

static int callback_after_load(void *__skel)
{{
	/* you can initialize maps here */
	return 0;
}}"""

    def skel_user_c_main_sec(self, **kwargs) -> str:
        """Generate exclusive code snippet for user program main function section."""
        return ""

    def skel_lkm_header_sec(self, **kwargs) -> str:
        """Generate shared code snippet for LKM header section."""
        return """#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>"""

    def skel_lkm_impl_sec(self, **kwargs) -> str:
        """Generate shared code snippet for LKM implementation section."""
        return ""

    def skel_lkm_init_exit(self, **kwargs) -> str:
        """Generate exclusive code snippet for LKM initialization and exit functions."""
        return ""

    def skel_lkm_makefile(self, **kwargs) -> str:
        """Generate exclusive code snippet for LKM Makefile."""
        return ""

    def add_author_version_info(self, code: str, file_type: str) -> str:
        """Add author and version information to generated code."""
        if not self.author_name or not self.version:
            return code

        if file_type == 'c':
            comment = f"/*\\n * Author: {self.author_name}\\n * Version: {self.version}\\n */\\n\\n"
        elif file_type == 'makefile':
            comment = f"# Author: {self.author_name}\\n# Version: {self.version}\\n\\n"
        else:
            comment = f"# Author: {self.author_name}, Version: {self.version}\\n\\n"

        return comment + code

    def generate_file(self, file_path: str, content: str, file_type: str = 'c') -> None:
        """Generate a file with the given content."""
        content_with_info = self.add_author_version_info(content, file_type)
        with open(file_path, 'w') as f:
            f.write(content_with_info)
