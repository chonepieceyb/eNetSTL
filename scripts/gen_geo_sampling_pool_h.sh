#!/bin/bash

set -eo pipefail

source $(
    cd "$(dirname "$0")"
    pwd
)"/"common.sh

python3 "$PROJECT_DIR/src/python/gen_geo.py" \
    -p 2 -p 4 -p 6 -p 8 -p 10 \
    -o "$PROJECT_DIR/LKM/bpf_random_base_alg/geo_sampling_pool.h" \
    -o "$PROJECT_DIR/LKM/sk_nitro/geo_sampling_pool.h" \
    --cpus 40 \
    --max-geosampling-size 1024 \
    --geo-cnt-cap 2147483647 \
    --geo-cnt-type uint32_t
