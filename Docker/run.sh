#!/bin/bash
set -e 

sudo docker run --privileged \
    --rm \
    -v $(dirname $(pwd)):/root/enetstl \
    -v /sys/kernel/btf:/sys/kernel/btf enetstl:v0.1 /bin/sh \
    -c '/usr/local/sbin/bpftool btf dump file /sys/kernel/btf/vmlinux format c > /root/enetstl/src/bpf_kern/vmlinux.h'

sudo docker run  \
    -it \
	--hostname=enetstl-build \
	-v $(dirname $(pwd)):/root/enetstl \
	-v /sys/fs/bpf:/sys/fs/bpf \
	-v /lib/modules/$(uname -r)/build:/lib/modules/$(uname -r)/build \
	--network=host \
	--privileged \
	--runtime=runc \
    -w /root/enetstl \
	enetstl:v0.1