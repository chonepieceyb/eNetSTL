#!/bin/bash
source $(cd "$(dirname "$0")"; pwd)"/"common.sh 

set -e 

pushd $PROJECT_DIR > /dev/null


cmake -B build ./
rm -rf ./src/c/bpf_skel/*

cd ./build 

make -j $cpu ebpf_demo
make bpf_install

popd > /dev/null