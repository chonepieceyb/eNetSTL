#!/bin/bash

#TODO: merge this script with project_root/scripts/gen_vmlinux_h.sh, check if project_root/linux exists, if true dump vmlinux from there (the conten of this scripts ), if not use the contet of gen_vmlinux.h

source $(cd "$(dirname "$0")"; pwd)"/"common.sh 

OUTPUT=$BPF_KERN_DIR"vmlinux.h" 

if [ ! -f "$BPF_TOOL_PATH" ]; then
    BPF_TOOL_PATH=bpftool # use generic bpftool
fi

echo use boftool path: $BPF_TOOL_PATH
$BPF_TOOL_PATH btf dump file $PROJECT_DIR$LINUX/vmlinux format c > $OUTPUT 
