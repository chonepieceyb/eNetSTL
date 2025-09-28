#!/bin/bash
source $(cd "$(dirname "$0")"; pwd)"/"common.sh""

ENABLE_GDB=false
WAIT_GDB=false

function find_available_port() {
    local start_port=$1
    local end_port=$2
    local service=$3
    local port=$start_port

    while [ $port -le $end_port ]; do
        if ! netstat -tuln 2>/dev/null | grep -q ":$port "; then
            echo $port
            return 0
        fi
        port=$((port + 1))
    done

    echo -e "$COLOR_RED [ERROR] No available $service port found in range $start_port-$end_port $COLOR_OFF" >&2
    return 1
}

function echo_help() {
    echo "Usage: $0 [-gdb] [-S] [-p SESSION_PREFIX]"
    echo "  -gdb   Enable GDB server"
    echo "  -S     Wait for GDB to attach before starting"
    echo "  -p     Specify session prefix (default: kernel-testbed)"
    echo "add -s to start gdb"
    echo "add -S to hold on when enabling gdb"
    echo "run ./create_LKM_link.sh"
    echo "gdb vmlinux"
    echo "target remote :\$GDB_PORT"
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

# Select available ports
GDB_PORT=$(find_available_port 1567 1600 "GDB") || exit 1
SSH_PORT=$(find_available_port 3333 3400 "SSH") || exit 1

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

# Pass selected ports and arguments to the debug script
sudo tmux new-session -d -s $session_name "GDB_PORT=$GDB_PORT SSH_PORT=$SSH_PORT ${SCRIPT_DIR}/debug_kernel_testbed.sh $DEBUG_ARGS"

# Check if tmux session is alive after starting
sleep 2
if ! sudo tmux has-session -t $session_name 2>/dev/null; then
    echo -e "$COLOR_RED [ERROR] Failed to start tmux session: $session_name $COLOR_OFF"
    echo -e "$COLOR_RED [ERROR] The session may have crashed or failed to initialize $COLOR_OFF"
    exit 1
fi

# Display selected port information
echo -e "$COLOR_GREEN [INFO] GDB port: $GDB_PORT $COLOR_OFF"
echo -e "$COLOR_GREEN [INFO] SSH port: $SSH_PORT $COLOR_OFF"
echo -e "$COLOR_GREEN [INFO] Session name: $session_name $COLOR_OFF"
echo -e "$COLOR_GREEN [INFO] Session is running successfully $COLOR_OFF"
echo -e "$COLOR_GREEN [INFO] run sudo tmux attach -t $session_name  to attach to the testing session $COLOR_OFF"
echo -e "$COLOR_GREEN [INFO] run sudo tmux kill-session -t $session_name > /dev/null 2>&1  to kill testing session $COLOR_OFF"
echo -e "$COLOR_GREEN [INFO] or run ssh -p $SSH_PORT user@127.0.0.1 $COLOR_OFF"
echo_help