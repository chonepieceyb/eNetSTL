#!/bin/bash
source $(cd "$(dirname "$0")"; pwd)"/"common.sh

ENABLE_GDB=true
WAIT_GDB=true
GDB_PORT=5234
SSH_PORT=5022

echo -e "$COLOR_GREEN [INFO] Starting QEMU with SSH port: $SSH_PORT $COLOR_OFF"
echo -e "$COLOR_GREEN [INFO] Starting QEMU with GDB port: $GDB_PORT $COLOR_OFF"
echo -e "$COLOR_YELLOW [INFO] Use SSH: ssh -p $SSH_PORT wangxinshu@127.0.0.1 $COLOR_OFF"
echo -e "$COLOR_YELLOW [INFO] Use GDB: target remote :$GDB_PORT $COLOR_OFF"

# Execute QEMU command directly
sudo qemu-system-x86_64 --enable-kvm -m 4G -smp 4 -cpu host -boot c -hda ${PROJECT_DIR}kernel-simdnn.img -device virtio-net-pci,netdev=net0 -netdev user,hostfwd=tcp::${SSH_PORT}-:22,id=net0 -nographic -append 'root=/dev/sda2 console=ttyS0 nokaslr' -kernel ${PROJECT_DIR}${LINUX}/kernel/arch/x86/boot/bzImage -gdb tcp::${GDB_PORT} -S