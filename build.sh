#!/bin/bash
set -e

# Default values
USE_DOCKER=false
DOCKER_IMAGE="chonepieceyb/enetstl:v0.1"

# Function to print help
print_help() {
    echo "Usage: $0 [OPTIONS] [CMAKE_ARGS...]"
    echo ""
    echo "Options:"
    echo "  -d, --docker              Build using Docker container"
    echo "  -i, --image IMAGE         Specify Docker image (default: $DOCKER_IMAGE)"
    echo "  -h, --help                 Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                        # Build locally"
    echo "  $0 -d                     # Build using Docker"
    echo "  $0 -d -i my/image:tag    # Build using custom Docker image"
    echo "  $0 -DLOG_LEVEL=2          # Build locally with CMake options"
    echo "  $0 -d -DLOG_LEVEL=2       # Build using Docker with CMake options"
}

# Parse command line arguments
CMAKE_ARGS=()
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--docker)
            USE_DOCKER=true
            shift
            ;;
        -i|--image)
            DOCKER_IMAGE="$2"
            shift 2
            ;;
        -h|--help)
            print_help
            exit 0
            ;;
        -*)
            # Pass through CMake arguments
            CMAKE_ARGS+=("$1")
            shift
            ;;
        *)
            # Pass through CMake arguments
            CMAKE_ARGS+=("$1")
            shift
            ;;
    esac
done

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

# Docker build functionality
if [ "$USE_DOCKER" = true ]; then
    print_status "Building using Docker container..."
    print_status "Docker image: $DOCKER_IMAGE"

    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed or not in PATH!"
        exit 1
    fi

    # Check if Docker is running
    if ! docker info &> /dev/null; then
        print_error "Docker is not running. Please start Docker daemon."
        exit 1
    fi

    # Check if we have permission to run Docker
    if ! docker ps &> /dev/null; then
        print_error "Permission denied when trying to run Docker."
        print_error "Please add your user to the docker group or run with sudo."
        exit 1
    fi

    # Prepare Docker mount options
    LINUX_MOUNT=""
    if [ -d "${PROJECT_ROOT}/linux" ]; then
        LINUX_MOUNT="-v ${PROJECT_ROOT}/linux:/root/enetstl/linux"
        print_status "Linux folder detected and will be mounted"
    fi

    # Prepare CMake arguments string
    CMAKE_ARGS_STR=""
    for arg in "${CMAKE_ARGS[@]}"; do
        CMAKE_ARGS_STR="${CMAKE_ARGS_STR} ${arg}"
    done

    print_status "CMake arguments: ${CMAKE_ARGS_STR}"

    # Run Docker build
    print_status "Starting Docker container for build..."

    docker run --rm \
        -v "${PROJECT_ROOT}":/root/enetstl \
        ${LINUX_MOUNT} \
        --runtime=runc \
        -w /root/enetstl \
        ${DOCKER_IMAGE} \
        /bin/bash -c "./build.sh ${CMAKE_ARGS_STR}"

    DOCKER_EXIT_CODE=$?

    if [ $DOCKER_EXIT_CODE -eq 0 ]; then
        echo ""
        echo -e "${GREEN}=== Docker build completed successfully! ===${NC}"
        echo -e "${GREEN}Build artifacts are in: ${BUILD_DIR}${NC}"
        exit 0
    else
        print_error "Docker build failed with exit code: $DOCKER_EXIT_CODE"
        exit $DOCKER_EXIT_CODE
    fi
fi

# Local build (non-Docker)
echo -e "${BLUE}=== eNetSTL Build Script ===${NC}"
echo -e "${BLUE}Project root: ${PROJECT_ROOT}${NC}"
echo -e "${BLUE}Build directory: ${BUILD_DIR}${NC}"
echo ""

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
    CMAKE_ARGS_LOCAL="-DLOG_LEVEL=0"

    # Add additional CMake arguments from command line
    for arg in "${CMAKE_ARGS[@]}"; do
        CMAKE_ARGS_LOCAL="${CMAKE_ARGS_LOCAL} ${arg}"
    done

    if [ ${#CMAKE_ARGS[@]} -gt 0 ]; then
        print_status "Additional CMake arguments: ${CMAKE_ARGS[*]}"
    fi

    cmake ${CMAKE_ARGS_LOCAL} ..

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