#!/bin/bash

source $(cd "$(dirname "$0")"; pwd)"/"common.sh

function echo_help() {
    echo "add -s to start gdb"
    echo "add -S to hold on when enabling gdb"
    echo "run ./create_LKM_link.sh"
    echo "gdb vmlinux"
    echo "target remote :1567"
    echo "lx-symbols to reload vmlinux and LKMs symbol"
}

set -e 

echo_help

${SCRIPT_DIR}/copy_LKM.sh

#add -S to wait for gdb

sudo qemu-system-x86_64 --enable-kvm -m 4G -smp 4 -cpu host -boot c \
    -hda ${PROJECT_DIR}testing/kernel-testbed.img -device virtio-net-pci,netdev=net0    \
    -netdev user,hostfwd=tcp::3333-:22,id=net0 -nographic -append " root=/dev/sda2 console=ttyS0 nokaslr" \
    -kernel ${PROJECT_DIR}${LINUX}/arch/x86_64/boot/bzImage -gdb tcp::1567