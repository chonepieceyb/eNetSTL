#!/bin/bash

set -eo pipefail

if [[ "$(id -u)" != "0" ]]; then
    exec sudo "$0" "$@"
fi

source $(
    cd "$(dirname "$0")"
    pwd
)"/"common.sh

if [[ ! -x "$PROJECT_DIR/bin/clear_struct_ops_user" ]]; then
    echo "please build the executables before running this script"
    exit 1
fi

if [[ -n "$1" ]]; then
    "$PROJECT_DIR/bin/clear_struct_ops_user" "$1"
else
    echo >&2 "scanning filenames under /sys/fs/bpf"
    find /sys/fs/bpf -maxdepth 1 \
        -type f \
        ! -name "snap" \
        ! -name "tc" \
        ! -name "count_map" \
        -exec basename {} \; \
    | xargs -I{} "$0" {}
fi
