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

session_name="kernel-testbed-yb"

sudo tmux kill-session -t $session_name > /dev/null 2>&1

set -e
sudo tmux new-session -d -s $session_name "${SCRIPT_DIR}/debug_kernel_testbed.sh"

echo -e "$COLOR_GREEN [INFO] run sudo tmux attach -t $session_name  to attach to the testing session $COLOR_OFF"
echo -e "$COLOR_GREEN [INFO] run sudo tmux kill-session -t $session_name > /dev/null 2>&1  to kill testing session $COLOR_OFF"
echo -e "$COLOR_GREEN [INFO] or run ssh user@127.0.0.1:3333 $COLOR_OFF"
echo_help