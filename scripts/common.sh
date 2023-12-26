#!/bin/bash

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

cpu=$(cat /proc/cpuinfo | grep processor | wc -l)

LINUX=linux

SCRIPT_DIR=$(cd "$(dirname "$0")"; pwd)"/"

PROJECT_DIR=$(cd "$(dirname "$SCRIPT_DIR")"; pwd)"/"

PATCH_DIR=$PROJECT_DIR"patches/"

BPF_KERN_DIR=$PROJECT_DIR"src/bpf_kern/"

BPF_TOOL_PATH=$PROJECT_DIR$LINUX"/tools/bpf/bpftool/bpftool"
