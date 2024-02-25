#!/bin/bash

set -eo pipefail

source $(
    cd "$(dirname "$0")"
    pwd
)"/"common.sh

if [[ ! -x "$PROJECT_DIR/bin/cuckoo_hash_collision_user" ]]; then
    echo "please build the executables before running this script"
    exit 1
fi

mkdir -p "$PROJECT_DIR/traces"
"$PROJECT_DIR/bin/cuckoo_hash_collision_user" "$PROJECT_DIR/traces" "$PROJECT_DIR/src/bpf_kern/cuckoo_hash_prefill.h"
cp "$PROJECT_DIR/src/bpf_kern/cuckoo_hash_prefill.h" "$PROJECT_DIR/LKM/cuckoo_hash/cuckoo_hash_prefill.h"
