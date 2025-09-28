#!/bin/bash
source $(cd "$(dirname "$0")"; pwd)"/"common.sh""

# Default configuration
ENABLE_GDB=false
WAIT_GDB=false
MEMORY_SIZE="4G"
CPU_CORES=4
DEBUG_LEVEL=1

function echo_help() {
    echo "Usage: $0 [OPTIONS]"
    echo "QEMU Kernel Debug Testbed Launcher"
    echo ""
    echo "OPTIONS:"
    echo "  -gdb                   Enable GDB server"
    echo "  -S                     Wait for GDB to attach before starting"
    echo "  -m, --memory SIZE      Set memory size (default: 4G)"
    echo "  -c, --cores NUM        Set CPU cores (default: 4)"
    echo "  --debug-level LEVEL    Set debug verbosity level 1-3 (default: 1)"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "NETWORKING:"
    echo "  SSH Access:           ssh -p \$SSH_PORT user@127.0.0.1"
    echo ""
    echo "DEBUGGING:"
    echo "  GDB:                 target remote :\$GDB_PORT"
    echo "  Kernel Debug:         gdb vmlinux"
    echo "  Load Symbols:         lx-symbols"
    echo "  LKM Link:            ./create_LKM_link.sh"
    echo ""
    echo "ENVIRONMENT VARIABLES:"
    echo "  GDB_PORT              GDB server port (default: 1567)"
    echo "  SSH_PORT              SSH forwarding port (default: 3333)"
    echo "  QEMU_IMG              Path to QEMU disk image"
    echo "  LINUX_PATH            Path to Linux kernel source"
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
    KERNEL_IMG="${PROJECT_DIR}${LINUX}/vmlinux"
    if [ ! -f "$KERNEL_IMG" ]; then
        log_error "Kernel image not found: $KERNEL_IMG"
        log_info "Set LINUX_PATH environment variable or ensure kernel is built"
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

    log_error "No available $service port found in range $start_port-$end_port"
    return 1
}

function setup_network_configuration() {
    log_debug "Setting up network configuration..."

    log_info "Network configuration:"
    log_info "  SSH Port: $SSH_PORT"
    if [ "$ENABLE_GDB" = true ]; then
        log_info "  GDB Port: $GDB_PORT"
    fi
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

# Use ports from environment or defaults, but find available ports if not specified
if [ -z "$GDB_PORT" ]; then
    GDB_PORT=$(find_available_port 1567 1600 "GDB") || exit 1
    log_info "Auto-selected GDB port: $GDB_PORT"
fi
if [ -z "$SSH_PORT" ]; then
    SSH_PORT=$(find_available_port 3333 3400 "SSH") || exit 1
    log_info "Auto-selected SSH port: $SSH_PORT"
fi

# Show help if no arguments provided
if [ $# -eq 0 ]; then
    echo_help
fi

log_info "=== QEMU Kernel Debug Testbed ==="
log_info "Memory: $MEMORY_SIZE, CPU Cores: $CPU_CORES"

# Validate dependencies before starting
validate_dependencies

# Setup network configuration
setup_network_configuration

# Create QEMU command with dual network setup
QEMU_DISK="${QEMU_IMG:-${PROJECT_DIR}testing/kernel-testbed.img}"
KERNEL_IMG="${PROJECT_DIR}${LINUX}/vmlinux"

log_debug "Building QEMU command..."

# Base QEMU command
QEMU_CMD="sudo qemu-system-x86_64 --enable-kvm \
    -m $MEMORY_SIZE \
    -smp $CPU_CORES \
    -cpu host \
    -boot c \
    -hda $QEMU_DISK \
    -nographic \
    -append \"root=/dev/sda2 console=ttyS0 nokaslr net.ifnames=0\" \
    -kernel $KERNEL_IMG"

# Add single SSH network device
QEMU_CMD="$QEMU_CMD -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56"
QEMU_CMD="$QEMU_CMD -netdev user,hostfwd=tcp::${SSH_PORT}-:22,id=net0"

# Add second network device for XDP testing
# Using user network with DHCP to ensure interface comes up
QEMU_CMD="$QEMU_CMD -device virtio-net-pci,netdev=net1,mac=52:54:00:12:34:57"
QEMU_CMD="$QEMU_CMD -netdev user,id=net1,net=192.168.100.0/24,dhcpstart=192.168.100.10"

# Add GDB options if enabled
if [ "$ENABLE_GDB" = true ]; then
    QEMU_CMD="$QEMU_CMD -gdb tcp::${GDB_PORT}"
    if [ "$WAIT_GDB" = true ]; then
        QEMU_CMD="$QEMU_CMD -S"
        log_info "GDB wait mode enabled - QEMU will pause until GDB attaches"
    fi
fi


log_info "Starting QEMU with configuration:"
log_info "  SSH Port: $SSH_PORT"
if [ "$ENABLE_GDB" = true ]; then
    log_info "  GDB: enabled on port $GDB_PORT"
    log_info "  Use: gdb $KERNEL_IMG"
    log_info "  Then: target remote :$GDB_PORT"
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
    exit 1
fi

log_info "QEMU started successfully (PID: $QEMU_PID)"
log_info "Press Ctrl+C to stop QEMU"

# Wait for QEMU to finish
wait $QEMU_PID
log_info "QEMU session ended"