#!/bin/bash
source $(cd "$(dirname "$0")"; pwd)"/"common.sh""

ENABLE_GDB=false
WAIT_GDB=false

function echo_help() {
    echo "Usage: $0 [-gdb] [-S]"
    echo "  -gdb   Enable GDB server"
    echo "  -S     Wait for GDB to attach before starting"
    echo "add -s to start gdb"
    echo "add -S to hold on when enabling gdb"
    echo "run ./create_LKM_link.sh"
    echo "gdb vmlinux"
    echo "target remote :$GDB_PORT"
    echo "lx-symbols to reload vmlinux and LKMs symbol"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -gdb)
            ENABLE_GDB=true
            shift
            ;;
        -S)
            WAIT_GDB=true
            shift
            ;;
        -h|--help)
            echo_help
            exit 0
            ;;
        *)
            echo -e "$COLOR_RED [ERROR] Unknown option: $1 $COLOR_OFF"
            echo_help
            exit 1
            ;;
    esac
done

set -e

# Use ports from environment or defaults
GDB_PORT=${GDB_PORT:-1567}
SSH_PORT=${SSH_PORT:-3333}

echo_help

# ${SCRIPT_DIR}/copy_LKM.sh

echo -e "$COLOR_GREEN [INFO] Starting QEMU with SSH port: $SSH_PORT $COLOR_OFF"
if [ "$ENABLE_GDB" = true ]; then
    echo -e "$COLOR_GREEN [INFO] Starting QEMU with GDB port: $GDB_PORT $COLOR_OFF"
    echo -e "$COLOR_YELLOW [INFO] Use SSH: ssh -p $SSH_PORT user@127.0.0.1 $COLOR_OFF"
    echo -e "$COLOR_YELLOW [INFO] Use GDB: target remote :$GDB_PORT $COLOR_OFF"
else
    echo -e "$COLOR_YELLOW [INFO] GDB server disabled $COLOR_OFF"
fi

# Build QEMU command
QEMU_CMD="sudo qemu-system-x86_64 --enable-kvm -m 4G -smp 4 -cpu host -boot c \
    -hda ${PROJECT_DIR}testing/kernel-testbed.img -device virtio-net-pci,netdev=net0    \
    -netdev user,hostfwd=tcp::${SSH_PORT}-:22,id=net0 -nographic -append \" root=/dev/sda2 console=ttyS0 nokaslr\" \
    -kernel ${PROJECT_DIR}${LINUX}/vmlinux"

# Add GDB options if enabled
if [ "$ENABLE_GDB" = true ]; then
    QEMU_CMD="$QEMU_CMD -gdb tcp::${GDB_PORT}"
    if [ "$WAIT_GDB" = true ]; then
        QEMU_CMD="$QEMU_CMD -S"
    fi
fi

# Execute QEMU command
eval $QEMU_CMD