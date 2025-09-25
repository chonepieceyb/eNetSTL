#!/bin/bash
set -e

# Get the script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}"
BUILD_DIR="${PROJECT_ROOT}/build"

# Color output for better UX
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== eNetSTL Build Script ===${NC}"
echo -e "${BLUE}Project root: ${PROJECT_ROOT}${NC}"
echo -e "${BLUE}Build directory: ${BUILD_DIR}${NC}"
echo ""

# Function to print status messages
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the right directory
if [ ! -f "CMakeLists.txt" ]; then
    print_error "CMakeLists.txt not found in current directory!"
    print_error "Please run this script from the project root directory."
    exit 1
fi

# Create build directory if it doesn't exist
if [ ! -d "${BUILD_DIR}" ]; then
    print_status "Creating build directory..."
    mkdir -p "${BUILD_DIR}"
    if [ $? -ne 0 ]; then
        print_error "Failed to create build directory!"
        exit 1
    fi
else
    print_status "Build directory already exists"
fi

# Change to build directory
print_status "Changing to build directory..."
cd "${BUILD_DIR}"

# Check if CMake needs to be reconfigured
if [ ! -f "CMakeCache.txt" ] || [ "CMakeLists.txt" -nt "CMakeCache.txt" ]; then
    print_status "Running CMake configuration..."

    # Default CMake options
    CMAKE_ARGS="-DLOG_LEVEL=0"

    # Allow passing additional CMake arguments
    if [ $# -gt 0 ]; then
        CMAKE_ARGS="${CMAKE_ARGS} $*"
        print_status "Additional CMake arguments: $*"
    fi

    cmake ${CMAKE_ARGS} ..

    if [ $? -ne 0 ]; then
        print_error "CMake configuration failed!"
        exit 1
    fi
else
    print_status "CMake configuration up to date"
fi

# Get number of CPU cores for parallel compilation
if command -v nproc &> /dev/null; then
    JOBS=$(nproc)
elif command -v sysctl &> /dev/null; then
    JOBS=$(sysctl -n hw.ncpu)
else
    JOBS=4  # Fallback to 4 jobs
fi

print_status "Building with ${JOBS} parallel jobs..."

# Run make
make -j${JOBS}

if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}=== Build completed successfully! ===${NC}"
    echo -e "${GREEN}Build artifacts are in: ${BUILD_DIR}${NC}"

    # Show some useful information
    if [ -d "bin" ]; then
        echo -e "${BLUE}Executables:${NC}"
        ls -la bin/ 2>/dev/null | grep -E "^\-.*" | awk '{print "  " $9}'
    fi

    if [ -d "install" ]; then
        echo -e "${BLUE}BPF objects:${NC}"
        ls -la install/bpf_kern_objs/ 2>/dev/null | head -10
    fi
else
    print_error "Build failed!"
    exit 1
fi