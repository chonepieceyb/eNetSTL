#!/bin/bash

set -eo pipefail

source $(
    cd "$(dirname "$0")"
    pwd
)"/"common.sh

TRACES_DIR="$PROJECT_DIR/traces"
PCAP_DIR="$PROJECT_DIR/pcap"

SRC_MAC="00:15:4d:13:70:4f"
DST_MAC="00:15:4d:13:72:80"

mkdir -p "$TRACES_DIR"
mkdir -p "$PCAP_DIR"

find "$TRACES_DIR" -name "*_trace" | LC_ALL=C.UTF-8 sort | while read -r input_file; do
    output_file="$PCAP_DIR/$(basename "$input_file" _trace).pcap"
    echo -e "${COLOR_GREEN}Converting trace '$input_file' to pcap '$output_file'${COLOR_OFF}"
    ./scripts/classbench-to-pcap.py \
        -i "$input_file" \
        -o "$output_file" \
        -s "$SRC_MAC" \
        -d "$DST_MAC"
done
