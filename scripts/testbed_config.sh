#!/bin/bash

# Testbed Configuration Management Script for eNetSTL
# This script reads or creates kernel testbed configuration files

set -e

# Get project root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Default configuration file path
DEFAULT_CONFIG_PATH="$PROJECT_ROOT/configs/kernel_testbed.conf"
CONFIG_PATH="${KERNDBG_CONFIG_PATH:-$DEFAULT_CONFIG_PATH}"

# Default configuration values
DEFAULT_SSH_PORT=3333
DEFAULT_GDB_PORT=1567
DEFAULT_GDB_ENABLE=true
DEFAULT_VM_USER=seu
DEFAULT_VM_PASSWORD=123456
DEFAULT_TMUX_PREFIX=kernel_dbg
DEFAULT_FORCE_CLEAN_SESSION=true

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to create default configuration file
create_default_config() {
    local config_file="$1"

    print_info "Creating default configuration file: $config_file"

    # Create configs directory if it doesn't exist
    mkdir -p "$(dirname "$config_file")"

    cat > "$config_file" << EOF
# Kernel Testbed Configuration File
# This file contains configuration for kernel debugging testbeds

# SSH configuration
KERNDBG_SSH_PORT=$DEFAULT_SSH_PORT
KERNDBG_VM_USER=$DEFAULT_VM_USER
KERNDBG_VM_PASSWORD=$DEFAULT_VM_PASSWORD

# GDB configuration
KERNDBG_GDB_PORT=$DEFAULT_GDB_PORT
KERNDBG_GDB_ENABLE_AT_START=$DEFAULT_GDB_ENABLE

# Session management
KERNDBG_TMUX_SESSION_PREFIX=$DEFAULT_TMUX_PREFIX
KERNDBG_FORCE_CLEAN_SESSION=$DEFAULT_FORCE_CLEAN_SESSION

# Paths (relative to project root)
KERNDBG_LINUX_SRC_DIR=linux
KERNDBG_LKM_BUILD_DIR=src/LKMs
KERNDBG_BIN_BUILD_DIR=bin
KERNDBG_BPF_OBJ_DIR=install/bpf_kern_objs

# Network configuration
KERNDBG_TEST_INTERFACE=ens2f0np0

# Additional kernel boot parameters
KERNDBG_KERNEL_BOOT_PARAMS="console=ttyS0"
EOF

    print_success "Default configuration file created successfully"
}

# Function to read configuration file
read_config() {
    local config_file="$1"

    if [[ ! -f "$config_file" ]]; then
        print_warning "Configuration file not found: $config_file"
        print_info "Creating default configuration..."
        create_default_config "$config_file"
    fi

    print_info "Reading configuration from: $config_file"

    # Source the configuration file, but with safety checks
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue

        # Export variables safely
        if [[ "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then
            export "$line"
        fi
    done < "$config_file"

    print_success "Configuration loaded successfully"
}

# Function to validate configuration
validate_config() {
    local errors=0

    # Validate SSH port
    if ! [[ "$KERNDBG_SSH_PORT" =~ ^[0-9]+$ ]] || [[ "$KERNDBG_SSH_PORT" -lt 1 ]] || [[ "$KERNDBG_SSH_PORT" -gt 65535 ]]; then
        print_error "Invalid SSH port: $KERNDBG_SSH_PORT"
        ((errors++))
    fi

    # Validate GDB port
    if ! [[ "$KERNDBG_GDB_PORT" =~ ^[0-9]+$ ]] || [[ "$KERNDBG_GDB_PORT" -lt 1 ]] || [[ "$KERNDBG_GDB_PORT" -gt 65535 ]]; then
        print_error "Invalid GDB port: $KERNDBG_GDB_PORT"
        ((errors++))
    fi

    # Validate boolean values
    if [[ "$KERNDBG_GDB_ENABLE_AT_START" != "true" && "$KERNDBG_GDB_ENABLE_AT_START" != "false" ]]; then
        print_error "Invalid KERNDBG_GDB_ENABLE_AT_START value: $KERNDBG_GDB_ENABLE_AT_START (must be true or false)"
        ((errors++))
    fi

    if [[ "$KERNDBG_FORCE_CLEAN_SESSION" != "true" && "$KERNDBG_FORCE_CLEAN_SESSION" != "false" ]]; then
        print_error "Invalid KERNDBG_FORCE_CLEAN_SESSION value: $KERNDBG_FORCE_CLEAN_SESSION (must be true or false)"
        ((errors++))
    fi

    # Check if required directories exist (or can be created)
    local linux_src_full="$PROJECT_ROOT/$KERNDBG_LINUX_SRC_DIR"
    if [[ ! -d "$linux_src_full" ]]; then
        print_warning "Linux source directory not found: $linux_src_full"
    fi

    if [[ $errors -gt 0 ]]; then
        print_error "Configuration validation failed with $errors errors"
        return 1
    fi

    print_success "Configuration validation passed"
    return 0
}

# Function to display configuration
show_config() {
    print_info "Current Configuration:"
    echo "  SSH Port: $KERNDBG_SSH_PORT"
    echo "  VM User: $KERNDBG_VM_USER"
    echo "  GDB Port: $KERNDBG_GDB_PORT"
    echo "  GDB Enable at Start: $KERNDBG_GDB_ENABLE_AT_START"
    echo "  TMUX Session Prefix: $KERNDBG_TMUX_SESSION_PREFIX"
    echo "  Force Clean Session: $KERNDBG_FORCE_CLEAN_SESSION"
    echo "  Linux Source Dir: $KERNDBG_LINUX_SRC_DIR"
    echo "  Test Interface: $KERNDBG_TEST_INTERFACE"
    echo "  Config File: $CONFIG_PATH"
}

# Common function to display KERNDBG_* configuration (for use by other scripts)
echo_kerndbg_config() {
    # Use a global flag to prevent duplicate display
    if [ "${KERNDBG_CONFIG_SHOWN:-0}" = "1" ]; then
        return 0
    fi

    # Colors for compatibility with scripts using COLOR_* variables
    local GREEN='\033[0;32m'
    local BLUE='\033[0;34m'
    local YELLOW='\033[1;33m'
    local NC='\033[0m' # No Color

    echo -e "${GREEN}[INFO] Reading configuration from: $CONFIG_PATH${NC}"
    echo -e "${GREEN}[SUCCESS] Configuration loaded successfully${NC}"
    echo -e "${GREEN}[SUCCESS] Configuration validation passed${NC}"
    echo -e "${BLUE}[INFO] Current Configuration:${NC}"
    echo -e "  ${BLUE}SSH Port:${NC} $KERNDBG_SSH_PORT"
    echo -e "  ${BLUE}VM User:${NC} $KERNDBG_VM_USER"
    echo -e "  ${BLUE}GDB Port:${NC} $KERNDBG_GDB_PORT"
    echo -e "  ${BLUE}GDB Enable at Start:${NC} $KERNDBG_GDB_ENABLE_AT_START"
    echo -e "  ${BLUE}TMUX Session Prefix:${NC} $KERNDBG_TMUX_SESSION_PREFIX"
    echo -e "  ${BLUE}Force Clean Session:${NC} $KERNDBG_FORCE_CLEAN_SESSION"
    echo -e "  ${BLUE}Linux Source Dir:${NC} $KERNDBG_LINUX_SRC_DIR"
    echo -e "  ${BLUE}Test Interface:${NC} $KERNDBG_TEST_INTERFACE"
    echo -e "  ${BLUE}Config File:${NC} $CONFIG_PATH"

    # Set flag to prevent duplicate display
    export KERNDBG_CONFIG_SHOWN=1
}

# Function to export configuration variables for other scripts
export_config_vars() {
    # Export all configuration variables for use by other scripts
    export KERNDBG_SSH_PORT
    export KERNDBG_VM_USER
    export KERNDBG_VM_PASSWORD
    export KERNDBG_GDB_PORT
    export KERNDBG_GDB_ENABLE_AT_START
    export KERNDBG_TMUX_SESSION_PREFIX
    export KERNDBG_FORCE_CLEAN_SESSION
    export KERNDBG_LINUX_SRC_DIR
    export KERNDBG_LKM_BUILD_DIR
    export KERNDBG_BIN_BUILD_DIR
    export KERNDBG_BPF_OBJ_DIR
    export KERNDBG_TEST_INTERFACE
    export KERNDBG_KERNEL_BOOT_PARAMS
    export PROJECT_ROOT

    # Note: All scripts must use KERNDBG_* prefixed variables
    # Backward compatibility variables removed - use KERNDBG_* variables only
}

# Main execution
main() {
    local action="${1:-show}"

    case "$action" in
        "read"|"load")
            read_config "$CONFIG_PATH"
            validate_config
            export_config_vars
            ;;
        "show")
            read_config "$CONFIG_PATH"
            validate_config
            show_config
            export_config_vars
            ;;
        "create")
            create_default_config "$CONFIG_PATH"
            ;;
        "validate")
            read_config "$CONFIG_PATH"
            validate_config
            ;;
        "export")
            read_config "$CONFIG_PATH"
            validate_config
            export_config_vars
            print_info "Configuration variables exported for subprocesses"
            ;;
        "help"|"-h"|"--help")
            echo "Usage: $0 [ACTION]"
            echo ""
            echo "Actions:"
            echo "  read/load    - Read and validate configuration, export variables"
            echo "  show         - Read, validate, and display configuration"
            echo "  create       - Create default configuration file"
            echo "  validate     - Validate existing configuration"
            echo "  export       - Export configuration variables for subprocesses"
            echo "  help         - Show this help message"
            echo ""
            echo "Environment Variables:"
            echo "  KERNDBG_CONFIG_PATH - Path to configuration file"
            echo "                          (default: \$PROJECT_ROOT/configs/kernel_testbed.conf)"
            ;;
        *)
            print_error "Unknown action: $action"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Execute main function with all arguments
main "$@"