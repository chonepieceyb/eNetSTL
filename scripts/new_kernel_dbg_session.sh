#!/bin/bash

# New Kernel Debug Session Script for eNetSTL
# This script creates new kernel debugging tmux sessions with configuration support

source $(cd "$(dirname "$0")"; pwd)/common.sh

# Load testbed configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG_FILE="${KERNDBG_CONFIG_PATH:-$PROJECT_ROOT/configs/kernel_testbed.conf}"
if [ -f "$CONFIG_FILE" ]; then
    # Export the KERNDBG variables directly from config file
    source <(grep "^KERNDBG_" "$CONFIG_FILE")
else
    echo "[ERROR] Configuration file not found: $CONFIG_FILE"
    exit 1
fi

function echo_help() {
    printf "Usage: %s [OPTIONS]\n" "$0"
    printf "\n"
    printf "Create new kernel debugging tmux session using configuration settings.\n"
    printf "\n"
    printf "OPTIONS:\n"
    echo '  -h, --help         Show this help message'
    printf "\n"
    printf "CONFIGURATION:\n"
    printf "  This script uses settings from kernel_testbed.conf:\n"
    echo '  - Session Prefix: $KERNDBG_TMUX_SESSION_PREFIX'
    echo '  - GDB Port: $KERNDBG_GDB_PORT'
    echo '  - SSH Port: $KERNDBG_SSH_PORT'
    echo '  - GDB Enable: $KERNDBG_GDB_ENABLE_AT_START'
    printf "\n"
    printf "DEBUG USAGE:\n"
    echo '  gdb vmlinux'
    echo '  target remote :$KERNDBG_GDB_PORT'
    echo '  lx-symbols to reload vmlinux and LKMs symbol'
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
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

# Main function for creating new kernel debug session
create_kernel_debug_session() {
    local session_name="$1"

    # Pass selected ports and arguments to the debug script
    sudo tmux new-session -d -s $session_name "${SCRIPT_DIR}/debug_kernel_testbed.sh"

    # Check if tmux session is alive after starting
    sleep 2
    if ! sudo tmux has-session -t $session_name 2>/dev/null; then
        echo -e "${COLOR_RED}[ERROR] Failed to start tmux session: $session_name${COLOR_OFF}"
        echo -e "${COLOR_RED}[ERROR] The session may have crashed or failed to initialize${COLOR_OFF}"
        return 1
    fi

    # Return session information for caller to display
    echo "SESSION_NAME=$session_name"
    echo "SSH_PORT=$KERNDBG_SSH_PORT"
    echo "GDB_PORT=$KERNDBG_GDB_PORT"
    echo "VM_USER=$KERNDBG_VM_USER"
    echo "VM_HOST=127.0.0.1"

    return 0
}

# Function for displaying session information
display_session_info() {
    local session_name="$1"
    local ssh_port="${2:-$KERNDBG_SSH_PORT}"
    local vm_user="${3:-$KERNDBG_VM_USER}"

    echo -e "${COLOR_GREEN}[INFO] Session name: $session_name${COLOR_OFF}"
    echo -e "${COLOR_GREEN}[INFO] Session is running successfully${COLOR_OFF}"
    echo -e "${COLOR_GREEN}[INFO] run sudo tmux attach -t $session_name  to attach to the testing session${COLOR_OFF}"
    echo -e "${COLOR_GREEN}[INFO] run sudo tmux kill-session -t $session_name > /dev/null 2>&1  to kill testing session${COLOR_OFF}"
    echo -e "${COLOR_GREEN}[INFO] or run ssh -p $ssh_port $vm_user@127.0.0.1${COLOR_OFF}"
}

# Script execution logic
main_session() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                echo_help
                return 0
                ;;
            *)
                echo -e "$COLOR_RED [ERROR] Unknown option: $1 $COLOR_OFF"
                echo_help
                return 1
                ;;
        esac
    done

    # Load configuration
    source "$SCRIPT_DIR/testbed_config.sh" && read_config "$CONFIG_FILE" >/dev/null 2>&1 && export_config_vars

    # Generate session name
    timestamp=$(date +"%Y%m%d_%H%M%S")
    session_prefix="$KERNDBG_TMUX_SESSION_PREFIX"
    session_name="$session_prefix-$timestamp"

    # Kill any existing sessions if configured to do so
    if [ "$KERNDBG_FORCE_CLEAN_SESSION" = "true" ]; then
        echo -e "$COLOR_YELLOW [INFO] Force cleaning up existing sessions... $COLOR_OFF"
        "${SCRIPT_DIR}/kill_kernel_dbg_session.sh" --force "$session_prefix" >/dev/null 2>&1
    fi

    # Create session and get info
    local session_info
    session_info=$(create_kernel_debug_session "$session_name")
    local exit_code=$?

    if [ $exit_code -ne 0 ]; then
        return $exit_code
    fi

    # Only display configuration and help in interactive mode
    if [ "${QUIET_MODE:-0}" != "1" ]; then
        echo_kerndbg_config

        # Parse session info and display
        eval "$session_info"
        display_session_info "$SESSION_NAME" "$SSH_PORT" "$VM_USER"

        echo ""
        echo_help
    else
        # In quiet mode, output structured data for parsing
        echo "$session_info"
    fi
}

# Script execution - call main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main_session "$@"
fi