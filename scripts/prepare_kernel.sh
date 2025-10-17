#!/bin/bash

source $(cd "$(dirname "$0")"; pwd)"/"common.sh

set -e

# Default ports (will be auto-selected if not provided)
DEFAULT_GDB_PORT=""
DEFAULT_SSH_PORT=""

function echo_help() {
    echo "Usage: $0 [OPTIONS]"
    echo "Prepare kernel debug environment with custom ports"
    echo ""
    echo "OPTIONS:"
    echo "  --gdb-port PORT      Specify GDB port (auto-selected if not provided)"
    echo "  --ssh-port PORT      Specify SSH port (auto-selected if not provided)"
    echo "  -h, --help           Show this help message"
    echo ""
    echo "EXAMPLES:"
    echo "  $0                                           # Auto-select ports"
    echo "  $0 --gdb-port 1568 --ssh-port 3334         # Use specific ports"
    echo "  $0 --gdb-port 1568                          # Auto-select SSH port only"
    echo "  $0 --ssh-port 3334                          # Auto-select GDB port only"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --gdb-port)
            DEFAULT_GDB_PORT="$2"
            shift 2
            ;;
        --ssh-port)
            DEFAULT_SSH_PORT="$2"
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

# Validate port numbers if provided
if [[ -n "$DEFAULT_GDB_PORT" && ! "$DEFAULT_GDB_PORT" =~ ^[0-9]+$ ]]; then
    echo -e "$COLOR_RED [ERROR] Invalid GDB port: $DEFAULT_GDB_PORT $COLOR_OFF"
    exit 1
fi

if [[ -n "$DEFAULT_SSH_PORT" && ! "$DEFAULT_SSH_PORT" =~ ^[0-9]+$ ]]; then
    echo -e "$COLOR_RED [ERROR] Invalid SSH port: $DEFAULT_SSH_PORT $COLOR_OFF"
    exit 1
fi

echo -e "$COLOR_GREEN [INFO] Starting kernel preparation... $COLOR_OFF"

# Build arguments for new_kernel_dbg_session.sh
SESSION_ARGS="-gdb"
if [[ -n "$DEFAULT_GDB_PORT" ]]; then
    SESSION_ARGS="$SESSION_ARGS --gdb-port $DEFAULT_GDB_PORT"
fi
if [[ -n "$DEFAULT_SSH_PORT" ]]; then
    SESSION_ARGS="$SESSION_ARGS --ssh-port $DEFAULT_SSH_PORT"
fi

# 1. Start new kernel debug session and check if successful
echo -e "$COLOR_YELLOW [INFO] Starting new kernel debug session... $COLOR_OFF"
echo -e "$COLOR_BLUE [DEBUG] Session args: $SESSION_ARGS $COLOR_OFF"

# Run with timeout to prevent hanging
SESSION_OUTPUT=$(timeout 30 ${SCRIPT_DIR}/new_kernel_dbg_session.sh $SESSION_ARGS 2>&1)
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
echo -e "$COLOR_BLUE [DEBUG] Session output: $SESSION_OUTPUT $COLOR_OFF"

# Extract SSH port from session output using more robust parsing
SSH_PORT=$(echo "$SESSION_OUTPUT" | grep -o "SSH port: [0-9]*" | head -1 | sed 's/SSH port: //')
if [ -z "$SSH_PORT" ]; then
    echo -e "$COLOR_RED [ERROR] Could not extract SSH port from debug session output $COLOR_OFF"
    echo -e "$COLOR_RED [ERROR] Session output: $SESSION_OUTPUT $COLOR_OFF"
    exit 1
fi

# Extract GDB port from session output
GDB_PORT=$(echo "$SESSION_OUTPUT" | grep -o "GDB port: [0-9]*" | head -1 | sed 's/GDB port: //')
if [ -z "$GDB_PORT" ]; then
    echo -e "$COLOR_RED [ERROR] Could not extract GDB port from debug session output $COLOR_OFF"
    echo -e "$COLOR_RED [ERROR] Session output: $SESSION_OUTPUT $COLOR_OFF"
    exit 1
fi

echo -e "$COLOR_BLUE [DEBUG] Extracted SSH port: '$SSH_PORT' $COLOR_OFF"
echo -e "$COLOR_BLUE [DEBUG] Extracted GDB port: '$GDB_PORT' $COLOR_OFF"

# Extract session name from session output using more robust parsing
SESSION_NAME=$(echo "$SESSION_OUTPUT" | grep -o "Session name: [^[:space:]]*" | sed 's/Session name: //')
if [ -z "$SESSION_NAME" ]; then
    echo -e "$COLOR_RED [ERROR] Could not extract session name from debug session output $COLOR_OFF"
    echo -e "$COLOR_RED [ERROR] Session output: $SESSION_OUTPUT $COLOR_OFF"
    exit 1
fi

echo -e "$COLOR_GREEN [INFO] Kernel debug session started successfully $COLOR_OFF"
echo -e "$COLOR_GREEN [INFO] Session name: $SESSION_NAME $COLOR_OFF"
echo -e "$COLOR_GREEN [INFO] SSH port: $SSH_PORT $COLOR_OFF"
echo -e "$COLOR_GREEN [INFO] GDB port: $GDB_PORT $COLOR_OFF"

# 2. Copy files to VM using separate script
echo -e "$COLOR_YELLOW [INFO] Calling copy_files_to_vm.sh with SSH port $SSH_PORT... $COLOR_OFF"
${SCRIPT_DIR}/copy_files_to_vm.sh -p $SSH_PORT

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