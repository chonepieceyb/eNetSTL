#!/bin/bash

source $(cd "$(dirname "$0")"; pwd)"/"common.sh 

OUTPUT=$BPF_KERN_DIR"vmlinux.h" 

if [ ! -z $BPF_TOOL_PATH ]; then 
    BPF_TOOL_PATH=bpftool #use generic bpftool 
fi 

$BPF_TOOL_PATH btf dump file /sys/kernel/btf/vmlinux format c > $OUTPUT 
