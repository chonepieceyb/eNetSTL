#!/bin/bash
source $(cd "$(dirname "$0")"; pwd)"/"common.sh""

ENABLE_GDB=false
WAIT_GDB=false

function echo_help() {
    echo "Usage: $0 [-gdb] [-S] [-p SESSION_PREFIX]"
    echo "  -gdb   Enable GDB server"
    echo "  -S     Wait for GDB to attach before starting"
    echo "  -p     Specify session prefix (default: kernel-testbed)"
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
        -p)
            SESSION_PREFIX="$2"
            shift 2
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

# Add timestamp to session_name
timestamp=$(date +"%Y%m%d_%H%M%S")
session_prefix="kernel-testbed"
if [ -n "$SESSION_PREFIX" ]; then
    session_prefix="$SESSION_PREFIX"
fi
session_name="$session_prefix-yangbin-$timestamp"

# Detect GDB port 1567 usage and select alternative port if needed
GDB_PORT=1567
while netstat -tuln 2>/dev/null | grep -q ":$GDB_PORT "; do
    GDB_PORT=$((GDB_PORT + 1))
    if [ $GDB_PORT -gt 1600 ]; then
        echo -e "$COLOR_RED [ERROR] No available GDB port found in range 1567-1600 $COLOR_OFF"
        exit 1
    fi
done

# Detect SSH port 3333 usage and select alternative port if needed
SSH_PORT=3333
while netstat -tuln 2>/dev/null | grep -q ":$SSH_PORT "; do
    SSH_PORT=$((SSH_PORT + 1))
    if [ $SSH_PORT -gt 3400 ]; then
        echo -e "$COLOR_RED [ERROR] No available SSH port found in range 3333-3400 $COLOR_OFF"
        exit 1
    fi
done

# Kill any existing sessions with matching pattern
echo -e "$COLOR_YELLOW [INFO] Cleaning up existing sessions... $COLOR_OFF"
sudo tmux list-sessions 2>/dev/null | grep -E "$session_prefix-yangbin-|kernel-testbed-yb-|kernel-testbed-" | while read -r session; do
    session_to_kill=$(echo "$session" | cut -d: -f1)
    echo -e "$COLOR_YELLOW [INFO] Killing session: $session_to_kill $COLOR_OFF"
    sudo tmux kill-session -t "$session_to_kill" > /dev/null 2>&1
done

set -e

# Build command arguments for debug script
DEBUG_ARGS=""
if [ "$ENABLE_GDB" = true ]; then
    DEBUG_ARGS="$DEBUG_ARGS -gdb"
fi
if [ "$WAIT_GDB" = true ]; then
    DEBUG_ARGS="$DEBUG_ARGS -S"
fi

# Pass all ports and arguments to the debug script
sudo tmux new-session -d -s $session_name "GDB_PORT=$GDB_PORT SSH_PORT=$SSH_PORT ${SCRIPT_DIR}/debug_kernel_testbed.sh $DEBUG_ARGS"

# Check if tmux session is alive after starting
sleep 2
if ! sudo tmux has-session -t $session_name 2>/dev/null; then
    echo -e "$COLOR_RED [ERROR] Failed to start tmux session: $session_name $COLOR_OFF"
    echo -e "$COLOR_RED [ERROR] The session may have crashed or failed to initialize $COLOR_OFF"
    exit 1
fi

echo -e "$COLOR_GREEN [INFO] GDB port: $GDB_PORT $COLOR_OFF"
echo -e "$COLOR_GREEN [INFO] SSH port: $SSH_PORT $COLOR_OFF"
echo -e "$COLOR_GREEN [INFO] Session name: $session_name $COLOR_OFF"
echo -e "$COLOR_GREEN [INFO] Session is running successfully $COLOR_OFF"
echo -e "$COLOR_GREEN [INFO] run sudo tmux attach -t $session_name  to attach to the testing session $COLOR_OFF"
echo -e "$COLOR_GREEN [INFO] run sudo tmux kill-session -t $session_name > /dev/null 2>&1  to kill testing session $COLOR_OFF"
echo -e "$COLOR_GREEN [INFO] or run ssh -p $SSH_PORT user@127.0.0.1 $COLOR_OFF"
echo_help