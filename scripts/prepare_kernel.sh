#!/bin/bash

# This script now uses testbed_config.sh for configuration management


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

#TODO fix this scripts: now the new_kernel_dbg_session.sh and copy_files_to_vm.sh do not need CLI args, simplify this scripts

set -e

function echo_help() {
    echo "Usage: $0 [OPTIONS]"
    echo "Prepare kernel debug environment"
    echo ""
    echo "This script uses configuration from kernel_testbed.conf"
    echo ""
    echo "OPTIONS:"
    echo "  -h, --help           Show this help message"
    echo ""
    echo "CONFIGURATION:"
    echo "  Ports and settings are loaded from kernel_testbed.conf:"
    echo "  - GDB Port: \$KERNDBG_GDB_PORT"
    echo "  - SSH Port: \$KERNDBG_SSH_PORT"
    echo "  - Linux Source: \$KERNDBG_LINUX_SRC_DIR"
    echo ""
    echo "EXAMPLES:"
    echo "  $0                  # Prepare with configuration settings"
    echo "  $0 --help           # Show this help message"
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

# Load configuration (don't display - will be shown by the session script)
source "$SCRIPT_DIR/testbed_config.sh" && read_config "$CONFIG_PATH" >/dev/null 2>&1 && export_config_vars

echo -e "$COLOR_GREEN [INFO] Starting kernel preparation... $COLOR_OFF"

# 1. Start new kernel debug session and check if successful
echo -e "$COLOR_YELLOW [INFO] Starting new kernel debug session... $COLOR_OFF"

# Call the new_kernel_dbg_session.sh script in quiet mode
SESSION_OUTPUT=$(QUIET_MODE=1 timeout 30 "$SCRIPT_DIR/new_kernel_dbg_session.sh" 2>&1)
EXIT_CODE=$?

if [ $EXIT_CODE -eq 124 ]; then
    echo -e "$COLOR_RED [ERROR] New kernel debug session timed out after 30 seconds $COLOR_OFF"
    echo -e "$COLOR_RED [ERROR] This might indicate tmux session issues or QEMU startup problems $COLOR_OFF"
    exit 1
elif [ $EXIT_CODE -ne 0 ]; then
    echo -e "$COLOR_RED [ERROR] Failed to start kernel debug session (exit code: $EXIT_CODE) $COLOR_OFF"
    echo "$SESSION_OUTPUT"
    exit 1
fi

echo -e "$COLOR_GREEN [SUCCESS] New kernel debug session started successfully! $COLOR_OFF"

# Extract session information from output
SESSION_INFO=$(echo "$SESSION_OUTPUT" | grep -E "^(SESSION_NAME|SSH_PORT|GDB_PORT|VM_USER|VM_HOST)=")
if [ -z "$SESSION_INFO" ]; then
    echo -e "$COLOR_RED [ERROR] Could not extract session information from debug session output $COLOR_OFF"
    echo -e "$COLOR_RED [ERROR] Session output: $SESSION_OUTPUT $COLOR_OFF"
    exit 1
fi

# Parse session information
eval "$SESSION_INFO"

echo -e "$COLOR_GREEN [INFO] Kernel debug session started successfully $COLOR_OFF"
echo -e "$COLOR_GREEN [INFO] Session name: $SESSION_NAME $COLOR_OFF"
echo -e "$COLOR_GREEN [INFO] SSH port: $SSH_PORT $COLOR_OFF"
echo -e "$COLOR_GREEN [INFO] GDB port: $GDB_PORT $COLOR_OFF"

# 2. Copy files to VM using function directly
echo -e "$COLOR_YELLOW [INFO] Copying files to VM... $COLOR_OFF"

# Source the copy script and call its function directly
source "$SCRIPT_DIR/copy_files_to_vm.sh"
copy_files_to_vm_main

if [ $? -ne 0 ]; then
    echo -e "$COLOR_RED [ERROR] Failed to copy files to VM $COLOR_OFF"
    exit 1
fi

# 3. Final verification
echo -e "$COLOR_YELLOW [INFO] Final verification... $COLOR_OFF"

# Check if tmux session is still running
if ! sudo tmux has-session -t $SESSION_NAME 2>/dev/null; then
    echo -e "$COLOR_RED [ERROR] Kernel debug session is not running $COLOR_OFF"
    exit 1
fi

echo -e "$COLOR_GREEN [INFO] Kernel debug session: RUNNING $COLOR_OFF"

echo -e "$COLOR_GREEN [SUCCESS] All operations completed successfully! $COLOR_OFF"
echo -e "$COLOR_GREEN [INFO] You can connect to the VM with: ssh -p $SSH_PORT seu@127.0.0.1 $COLOR_OFF"
echo -e "$COLOR_GREEN [INFO] You can attach to the debug session with: sudo tmux attach -t $SESSION_NAME $COLOR_OFF"
echo -e "$COLOR_GREEN [INFO] GDB port for debugging: $GDB_PORT $COLOR_OFF"