#!/bin/bash
set -e
RESDIR="$(pwd)/resources"

if [ ! -d "$RESDIR/tmp/" ]; then
    mkdir -p $RESDIR/tmp/
fi
tar xzvf $RESDIR/bpftool-libbpf-v7.3.0-sources-custom.tar.gz  -C  $RESDIR/tmp && \
tar xzvf $RESDIR/tools.tar.gz  -C $RESDIR/tmp && \

sudo docker build --network=host --build-arg KERNEL_VERSION="$(uname -r)" -t enetstl:v0.1 -f $(pwd)/Dockerfile $RESDIR 

rm -rf ${RESDIR}/tmp