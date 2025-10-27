#!/bin/bash

# vmlinux.h Generation Script for eNetSTL
# This script generates vmlinux.h header file for BPF compilation
# Merged functionality from gen_vmlinux_h_test.sh

source $(cd "$(dirname "$0")"; pwd)/common.sh

# Set project paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Set default values
OUTPUT_FILE="$PROJECT_ROOT/src/bpf_kern/vmlinux.h"
BTF_SOURCE="compiled"  # Can be "system" or "compiled"
KERNEL_PATH="$PROJECT_ROOT/linux/vmlinux"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    printf "${BLUE}[INFO]${NC} %s\n" "$1"
}

print_success() {
    printf "${GREEN}[SUCCESS]${NC} %s\n" "$1"
}

print_warning() {
    printf "${YELLOW}[WARNING]${NC} %s\n" "$1"
}

print_error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1"
}

# Function to show help
show_help() {
    printf "Usage: %s [OPTIONS]\n" "$0"
    printf "\n"
    printf "Generate vmlinux.h header file for BPF compilation from BTF information.\n"
    printf "\n"
    printf "OPTIONS:\n"
    echo '  -s, --source SOURCE     BTF source: system or compiled (default: compiled)'
    echo '  -o, --output FILE       Output file path (default: $PROJECT_ROOT/src/c/bpf_skel/vmlinux.h)'
    echo '  -k, --kernel PATH       Path to compiled vmlinux (for compiled source)'
    echo '  -b, --bpftool PATH      Path to bpftool (default: bpftool)'
    echo '  -h, --help              Show this help message'
    printf "\n"
    printf "SOURCES:\n"
    echo '  system     - Use /sys/kernel/btf/vmlinux (running kernel)'
    echo '  compiled   - Use compiled vmlinux from kernel source'
    printf "\n"
    printf "EXAMPLES:\n"
    echo '  $0                                    # Generate from compiled kernel (default)'
    echo '  $0 --source system                    # Generate from system BTF'
    echo '  $0 --source compiled --kernel ./vmlinux  # Generate from specific compiled kernel'
    echo '  $0 -o /path/to/vmlinux.h               # Custom output path'
}

# Function to validate bpftool
validate_bpftool() {
    local bpftool_path="$1"

    if ! command -v "$bpftool_path" &> /dev/null; then
        print_error "bpftool not found: $bpftool_path"
        print_info "Please install bpftool or provide correct path with -b option"
        return 1
    fi

    # Check if bpftool supports BTF operations
    # Test if BTF subcommand exists (help will succeed if BTF is supported)
    if ! "$bpftool_path" btf help >/dev/null 2>&1; then
        print_error "bpftool does not support BTF operations: $bpftool_path"
        print_info "Your bpftool version may be too old. Please update to a newer version."
        return 1
    fi

    print_info "Using bpftool: $bpftool_path"
    return 0
}

# Function to generate vmlinux.h from system BTF
generate_from_system() {
    local bpftool_path="$1"
    local output_file="$2"

    printf "${BLUE}[INFO]${NC} Generating vmlinux.h from system BTF [/sys/kernel/btf/vmlinux]\n"

    if [[ ! -f "/sys/kernel/btf/vmlinux" ]]; then
        print_error "System BTF not found: /sys/kernel/btf/vmlinux"
        print_info "Make sure your kernel was compiled with CONFIG_DEBUG_INFO_BTF=y"
        print_info "Or try using 'compiled' source with a compiled vmlinux file"
        return 1
    fi

    # Create output directory if it doesn't exist
    mkdir -p "$(dirname "$output_file")"

    # Generate vmlinux.h
    if "$bpftool_path" btf dump file /sys/kernel/btf/vmlinux format c > "$output_file" 2>/dev/null; then
        print_success "vmlinux.h generated successfully from system BTF"
        print_info "Output file: $output_file"
        return 0
    else
        print_error "Failed to generate vmlinux.h from system BTF"
        return 1
    fi
}

# Function to generate vmlinux.h from compiled kernel
generate_from_compiled() {
    local bpftool_path="$1"
    local kernel_file="$2"
    local output_file="$3"

    print_info "Generating vmlinux.h from compiled kernel: $kernel_file"

    if [[ ! -f "$kernel_file" ]]; then
        print_error "Kernel file not found: $kernel_file"
        print_info "Provide correct path with -k option or ensure kernel is built"
        return 1
    fi

    # Create output directory if it doesn't exist
    mkdir -p "$(dirname "$output_file")"

    # Generate vmlinux.h
    if "$bpftool_path" btf dump file "$kernel_file" format c > "$output_file" 2>/dev/null; then
        print_success "vmlinux.h generated successfully from compiled kernel"
        print_info "Output file: $output_file"
        return 0
    else
        print_error "Failed to generate vmlinux.h from compiled kernel"
        return 1
    fi
}

# Function to verify generated file
verify_output() {
    local output_file="$1"

    if [[ ! -f "$output_file" ]]; then
        print_error "Output file not created: $output_file"
        return 1
    fi

    local file_size=$(stat -f%z "$output_file" 2>/dev/null || stat -c%s "$output_file" 2>/dev/null || echo "0")

    if [[ $file_size -eq 0 ]]; then
        print_error "Output file is empty: $output_file"
        return 1
    fi

    # Check if it looks like a valid header file
    # if ! head -n 5 "$output_file" | grep -q "struct"; then
    #     print_warning "Output file may not be a valid vmlinux.h"
    # fi

    print_info "Generated file size: $file_size bytes"
    return 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--source)
            BTF_SOURCE="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -k|--kernel)
            KERNEL_PATH="$2"
            shift 2
            ;;
        -b|--bpftool)
            BPF_TOOL_PATH="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Validate BTF source
if [[ "$BTF_SOURCE" != "system" && "$BTF_SOURCE" != "compiled" ]]; then
    print_error "Invalid BTF source: $BTF_SOURCE. Must be 'system' or 'compiled'"
    exit 1
fi

# Set default bpftool path if not provided
if [[ -z "$BPF_TOOL_PATH" ]]; then
    BPF_TOOL_PATH="bpftool"
fi

print_info "=== vmlinux.h Generation Script ==="
print_info "BTF Source: $BTF_SOURCE"
print_info "Output File: $OUTPUT_FILE"

# Validate bpftool
if ! validate_bpftool "$BPF_TOOL_PATH"; then
    exit 1
fi

# Generate vmlinux.h based on source
case "$BTF_SOURCE" in
    "system")
        if ! generate_from_system "$BPF_TOOL_PATH" "$OUTPUT_FILE"; then
            exit 1
        fi
        ;;
    "compiled")
        if ! generate_from_compiled "$BPF_TOOL_PATH" "$KERNEL_PATH" "$OUTPUT_FILE"; then
            exit 1
        fi
        ;;
esac

# Verify the generated file
if verify_output "$OUTPUT_FILE"; then
    print_success "vmlinux.h generation completed successfully!"
else
    exit 1
fi

