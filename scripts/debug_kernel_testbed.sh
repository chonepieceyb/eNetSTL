#!/bin/bash
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

# Override with command line arguments if provided (for backward compatibility)
ENABLE_GDB=$KERNDBG_GDB_ENABLE_AT_START
WAIT_GDB=$KERNDBG_GDB_WAIT_FOR_ATTACH
MEMORY_SIZE="4G"
CPU_CORES=4
DEBUG_LEVEL=1

function echo_help() {
    echo "Usage: $0 [OPTIONS]"
    echo "QEMU Kernel Debug Testbed Launcher"
    echo ""
    echo "This script loads configuration from testbed_config.sh by default."
    echo "Command line options can override configuration values."
    echo ""
    echo "OPTIONS:"
    echo "  -m, --memory SIZE      Set memory size (default: 4G)"
    echo "  -c, --cores NUM        Set CPU cores (default: 4)"
    echo "  --debug-level LEVEL    Set debug verbosity level 1-3 (default: 1)"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "CONFIGURATION:"
    echo "  Configuration is loaded from: ${KERNDBG_CONFIG_PATH:-\$PROJECT_ROOT/configs/kernel_testbed.conf}"
    echo "  Key config variables: KERNDBG_SSH_PORT, KERNDBG_GDB_PORT, KERNDBG_VM_USER, etc."
    echo "  GDB settings: KERNDBG_GDB_ENABLE_AT_START, KERNDBG_GDB_WAIT_FOR_ATTACH"
    echo ""
    echo "NETWORKING:"
    echo "  SSH Access:           ssh -p \$KERNDBG_SSH_PORT \$KERNDBG_VM_USER@127.0.0.1"
    echo ""
    echo "DEBUGGING:"
    echo "  GDB:                 target remote :\$KERNDBG_GDB_PORT"
    echo "  Kernel Debug:         gdb vmlinux"
    echo "  Load Symbols:         lx-symbols"
    echo "  LKM Link:            ./create_LKM_link.sh"
    echo ""
    echo "ENVIRONMENT VARIABLES:"
    echo "  KERNDBG_CONFIG_PATH         Path to configuration file"
    echo "  QEMU_IMG                     Path to QEMU disk image"
    echo "  KERNDBG_LINUX_SRC_DIR       Path to Linux kernel source"
}

function log_debug() {
    if [ $DEBUG_LEVEL -ge 2 ]; then
        echo -e "$COLOR_BLUE [DEBUG] $1 $COLOR_OFF"
    fi
}

function log_info() {
    if [ $DEBUG_LEVEL -ge 1 ]; then
        echo -e "$COLOR_GREEN [INFO] $1 $COLOR_OFF"
    fi
}

function log_warn() {
    echo -e "$COLOR_YELLOW [WARN] $1 $COLOR_OFF"
}

function log_error() {
    echo -e "$COLOR_RED [ERROR] $1 $COLOR_OFF"
}

function validate_dependencies() {
    log_debug "Validating dependencies..."

    # Check if QEMU is installed
    if ! command -v qemu-system-x86_64 &> /dev/null; then
        log_error "QEMU is not installed. Please install qemu-system-x86"
        exit 1
    fi

    # Check if tmux is installed
    if ! command -v tmux &> /dev/null; then
        log_error "tmux is not installed. Please install tmux"
        exit 1
    fi

    # Check if kernel image exists
    KERNEL_IMG="${PROJECT_DIR}${KERNDBG_LINUX_SRC_DIR}/vmlinux"
    if [ ! -f "$KERNEL_IMG" ]; then
        log_error "Kernel image not found: $KERNEL_IMG"
        log_info "Set KERNDBG_LINUX_SRC_DIR environment variable or ensure kernel is built"
        exit 1
    fi

    # Check if QEMU disk image exists
    QEMU_DISK="${QEMU_IMG:-${PROJECT_DIR}testing/kernel-testbed.img}"
    if [ ! -f "$QEMU_DISK" ]; then
        log_error "QEMU disk image not found: $QEMU_DISK"
        log_info "Set QEMU_IMG environment variable or create disk image"
        exit 1
    fi

    log_debug "Dependencies validated successfully"
}


function setup_network_configuration() {
    log_debug "Setting up network configuration..."

    log_info "Network configuration:"
    log_info "  SSH Port: $KERNDBG_SSH_PORT"
    if [ "$ENABLE_GDB" = true ]; then
        log_info "  GDB Port: $GDB_PORT"
    fi
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -m|--memory)
            MEMORY_SIZE="$2"
            shift 2
            ;;
        -c|--cores)
            CPU_CORES="$2"
            shift 2
            ;;
        --debug-level)
            DEBUG_LEVEL="$2"
            shift 2
            ;;
        -h|--help)
            echo_help
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            echo_help
            exit 1
            ;;
    esac
done

# Validate debug level
if ! [[ "$DEBUG_LEVEL" =~ ^[1-3]$ ]]; then
    log_error "Debug level must be 1, 2, or 3"
    exit 1
fi

set -e

# Validate that required ports from configuration are available
if [ -z "$KERNDBG_GDB_PORT" ]; then
    log_error "KERNDBG_GDB_PORT not configured in testbed_config.sh"
    log_error "Please set KERNDBG_GDB_PORT in your configuration"
    exit 1
fi

if [ -z "$KERNDBG_SSH_PORT" ]; then
    log_error "KERNDBG_SSH_PORT not configured in testbed_config.sh"
    log_error "Please set KERNDBG_SSH_PORT in your configuration"
    exit 1
fi

# Validate that required ports are available
if netstat -tuln 2>/dev/null | grep -q ":$KERNDBG_GDB_PORT "; then
    log_error "Configured GDB port $KERNDBG_GDB_PORT is already in use"
    log_error "Please free the port or update KERNDBG_GDB_PORT in testbed_config.sh"
    exit 1
fi

if netstat -tuln 2>/dev/null | grep -q ":$KERNDBG_SSH_PORT "; then
    log_error "Configured SSH port $KERNDBG_SSH_PORT is already in use"
    log_error "Please free the port or update KERNDBG_SSH_PORT in kernel_testbed.conf"
    exit 1
fi

# Main execution logic - can be called as function or script
main_qemu_testbed() {
    # Show help if --help is passed
    for arg in "$@"; do
        if [[ "$arg" == "-h" || "$arg" == "--help" ]]; then
            echo_help
            return 0
        fi
    done

    # Load and display configuration using common function
    source "$SCRIPT_DIR/testbed_config.sh" && read_config "$CONFIG_FILE" >/dev/null 2>&1 && export_config_vars
    echo_kerndbg_config

    log_info "=== QEMU Kernel Debug Testbed ==="
    log_info "Memory: $MEMORY_SIZE, CPU Cores: $CPU_CORES"

    # Validate dependencies before starting
    validate_dependencies

    # Setup network configuration
    setup_network_configuration

    # Create QEMU command with dual network setup
    QEMU_DISK="${QEMU_IMG:-${PROJECT_DIR}testing/kernel-testbed.img}"
    KERNEL_IMG="${PROJECT_DIR}${KERNDBG_LINUX_SRC_DIR}/vmlinux"

    log_debug "Building QEMU command..."

    # Base QEMU command
    QEMU_CMD="sudo qemu-system-x86_64 --enable-kvm \
        -m $MEMORY_SIZE \
        -smp $CPU_CORES \
        -cpu host \
        -boot c \
        -hda $QEMU_DISK \
        -nographic \
        -append \"root=/dev/sda2 ${KERNDBG_KERNEL_BOOT_PARAMS} nokaslr net.ifnames=0\" \
        -kernel $KERNEL_IMG"

    # Add single SSH network device
    QEMU_CMD="$QEMU_CMD -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56"
    QEMU_CMD="$QEMU_CMD -netdev user,hostfwd=tcp::${KERNDBG_SSH_PORT}-:22,id=net0"

    # Add second network device for XDP testing
    # Using user network with DHCP to ensure interface comes up
    QEMU_CMD="$QEMU_CMD -device virtio-net-pci,netdev=net1,mac=52:54:00:12:34:57"
    QEMU_CMD="$QEMU_CMD -netdev user,id=net1,net=192.168.100.0/24,dhcpstart=192.168.100.10"

    # Add GDB options if enabled
    if [ "$ENABLE_GDB" = true ]; then
        QEMU_CMD="$QEMU_CMD -gdb tcp::${KERNDBG_GDB_PORT}"
        if [ "$WAIT_GDB" = true ]; then
            QEMU_CMD="$QEMU_CMD -S"
            log_info "GDB wait mode enabled - QEMU will pause until GDB attaches"
        fi
    fi

    log_info "Starting QEMU with configuration:"
    log_info "  SSH Port: $KERNDBG_SSH_PORT"
    if [ "$ENABLE_GDB" = true ]; then
        log_info "  GDB: enabled on port $KERNDBG_GDB_PORT"
        log_info "  Use: gdb $KERNEL_IMG"
        log_info "  Then: target remote :$KERNDBG_GDB_PORT"
        log_info "  Then: lx-symbols"
    else
        log_info "  GDB: disabled"
    fi

    log_debug "QEMU Command: $QEMU_CMD"

    # Handle signals for clean shutdown
    trap 'log_info "Shutting down QEMU..."; kill $QEMU_PID 2>/dev/null; exit 0' SIGINT SIGTERM

    # Execute QEMU command
    log_info "Starting QEMU kernel testbed..."
    eval $QEMU_CMD &
    QEMU_PID=$!

    # Wait for QEMU to start
    sleep 3

    # Check if QEMU is still running
    if ! kill -0 $QEMU_PID 2>/dev/null; then
        log_error "QEMU failed to start"
        return 1
    fi

    log_info "QEMU started successfully (PID: $QEMU_PID)"
    log_info "Press Ctrl+C to stop QEMU"

    # Wait for QEMU to finish
    wait $QEMU_PID
    log_info "QEMU session ended"
}

# Function for starting kernel testbed without echo (for other scripts)
start_kernel_testbed_silent() {
    # Temporarily disable config display
    local CONFIG_SHOWN_BACKUP="${KERNDBG_CONFIG_SHOWN:-0}"
    export KERNDBG_CONFIG_SHOWN=1

    # Temporarily redirect log output
    exec 3>&1 4>&2
    exec 1>/dev/null 2>/dev/null

    # Call main function
    main_qemu_testbed --no-config "$@"
    local exit_code=$?

    # Restore output
    exec 1>&3 2>&4
    exec 3>&- 4>&-

    # Restore config state
    export KERNDBG_CONFIG_SHOWN="$CONFIG_SHOWN_BACKUP"

    return $exit_code
}

# Function to get VM connection info (returns structured data)
get_vm_info() {
    echo "SSH_PORT=$KERNDBG_SSH_PORT"
    echo "GDB_PORT=$KERNDBG_GDB_PORT"
    echo "VM_USER=$KERNDBG_VM_USER"
    echo "VM_HOST=127.0.0.1"
}

# Script execution - call main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main_qemu_testbed "$@"
fi