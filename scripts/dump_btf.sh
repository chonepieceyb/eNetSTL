#!/bin/bash

# BTF Dump Script using pahole
# Usage: ./dump_btf.sh <object_name> [install_dir]
# Example: ./dump_btf.sh test_static_ptr.o install/bpf_kern_objs/

set -e

# Color definitions
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

# Function to show usage
show_usage() {
    echo "BTF Dump Script using pahole"
    echo "Usage: $0 <object_name> [install_dir]"
    echo ""
    echo "Arguments:"
    echo "  object_name    Name of the BPF object file (e.g., test_static_ptr.o)"
    echo "  install_dir   Path to install directory (default: install/bpf_kern_objs/)"
    echo ""
    echo "Examples:"
    echo "  $0 test_static_ptr.o"
    echo "  $0 test_static_ptr.o install/bpf_kern_objs/"
    echo "  $0 my_bpf_object.o /path/to/install/dir/"
    echo ""
    echo "Requirements:"
    echo "  - pahole tool must be installed"
    echo "  - BPF object file must contain BTF information"
}

# Check dependencies
check_dependencies() {
    if ! command -v pahole &> /dev/null; then
        print_error "pahole is not installed or not in PATH"
        print_info "Install pahole with: sudo apt-get install dwarves"
        exit 1
    fi

    if ! command -v readelf &> /dev/null; then
        print_error "readelf is not installed or not in PATH"
        print_info "Install binutils with: sudo apt-get install binutils"
        exit 1
    fi

    if ! command -v objdump &> /dev/null; then
        print_error "objdump is not installed or not in PATH"
        print_info "Install binutils with: sudo apt-get install binutils"
        exit 1
    fi
}

# Function to dump BTF using pahole
dump_btf_pahole() {
    local object_file="$1"

    print_info "Dumping BTF information for: $object_file"

    # Check if file exists
    if [[ ! -f "$object_file" ]]; then
        print_error "Object file not found: $object_file"
        return 1
    fi

    # Check if file has BTF sections
    print_info "Checking for BTF sections..."
    if ! readelf -S "$object_file" | grep -q "\.BTF"; then
        print_warning "No .BTF section found in $object_file"
        return 1
    fi

    local btf_size=$(readelf -S "$object_file" 2>/dev/null | grep "\.BTF" | awk '{print $6}')
    local btf_ext_size=$(readelf -S "$object_file" 2>/dev/null | grep "\.BTF\.ext" | awk '{print $6}' || echo "0")

    print_success "BTF sections found:"
    echo "  .BTF size: $btf_size bytes"
    echo "  .BTF.ext size: $btf_ext_size bytes"

    echo ""
    print_info "=== BTF Type Information ==="

    # Try different pahole approaches, prioritizing -JV for BTF encoding
    if pahole -JV "$object_file"; then
        print_success "Successfully dumped BTF types with pahole -JV (BTF encoding verbose)"
    elif pahole -V "$object_file"; then
        print_success "Successfully dumped BTF types with pahole -V (verbose)"
    elif pahole "$object_file"; then
        print_success "Successfully dumped BTF types with pahole"
    elif pahole -C "$object_file"; then
        print_success "Successfully dumped BTF types with pahole -C"
    else
        print_warning "pahole could not parse BTF directly, trying alternative methods..."

        # Try to extract BTF raw data
        echo ""
        print_info "=== Raw BTF Section Dump ==="
        objdump -j .BTF -s "$object_file" 2>/dev/null || {
            print_error "Failed to dump raw BTF section"
            return 1
        }
    fi

    echo ""
    print_info "=== BTF String Section ==="

    # Extract string section from BTF
    local btf_offset_hex=$(readelf -S "$object_file" 2>/dev/null | grep "\.BTF" | awk '{print $5}')
    if [[ -n "$btf_offset_hex" ]]; then
        local btf_offset=$((0x$btf_offset_hex))
        local string_offset=$((btf_offset + 24))  # Skip BTF header

        # Try to extract strings
        if dd if="$object_file" bs=1 skip=$string_offset count=1000 2>/dev/null | strings | head -20; then
            print_success "Extracted BTF strings"
        else
            print_warning "Could not extract BTF strings cleanly"
        fi
    else
        print_warning "Could not determine BTF offset"
    fi

    echo ""
    print_info "=== Available Maps and Programs ==="

    # Extract map and program information from strings
    strings "$object_file" | grep -E "(map|prog)" | head -10 || print_warning "No map/program strings found"

    echo ""
    print_info "=== Data Structure Summary ==="

    # Extract struct/union/enum information
    strings "$object_file" | grep -E "(struct|union|enum)" | head -15 || print_warning "No struct/union/enum strings found"
}

# Function to show file information
show_file_info() {
    local object_file="$1"

    print_info "=== File Information ==="
    echo "File: $object_file"
    echo "Size: $(stat -c%s "$object_file" 2>/dev/null || stat -f%z "$object_file" 2>/dev/null || echo "unknown") bytes"
    echo "Type: $(file "$object_file")"
    echo ""

    print_info "=== ELF Sections ==="
    readelf -S "$object_file" 2>/dev/null | head -20
    echo "..."
}

# Main script logic
main() {
    # Check arguments
    if [[ $# -lt 1 ]]; then
        show_usage
        exit 1
    fi

    local object_name="$1"
    local install_dir="${2:-install/bpf_kern_objs/}"

    # Remove trailing slash if present
    install_dir="${install_dir%/}"

    print_info "BTF Dump Script Starting..."
    echo "Object name: $object_name"
    echo "Install directory: $install_dir"
    echo ""

    # Check dependencies
    check_dependencies

    # Construct full object file path
    local object_file="$install_dir/$object_name"

    # If the object_name is already a full path, use it directly
    if [[ "$object_name" == /* ]]; then
        object_file="$object_name"
    fi

    # Show file information
    show_file_info "$object_file"

    # Dump BTF information
    if dump_btf_pahole "$object_file"; then
        print_success "BTF dump completed successfully!"
    else
        print_error "Failed to dump BTF information"
        exit 1
    fi
}

# Handle help flag
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    show_usage
    exit 0
fi

# Run main function
main "$@"