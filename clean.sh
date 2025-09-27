#!/bin/bash
set -e

# Default values
USE_DOCKER=false
DOCKER_IMAGE="chonepieceyb/enetstl:v0.1"
CLEAN_TYPE="all"  # Options: "all", "cmake", "build"

# Function to print help
print_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -d, --docker              Clean using Docker container"
    echo "  -i, --image IMAGE         Specify Docker image (default: $DOCKER_IMAGE)"
    echo "  -t, --type TYPE           Clean type: all, cmake, build (default: all)"
    echo "  -h, --help                 Show this help message"
    echo ""
    echo "Clean types:"
    echo "  all        Complete clean (removes bin, build, install, bpf_skel)"
    echo "  cmake      Remove build artifacts only (make cmake_clean)"
    echo "  build      Remove entire build directory"
    echo ""
    echo "Examples:"
    echo "  $0                        # Clean locally (all)"
    echo "  $0 -d                     # Clean using Docker (all)"
    echo "  $0 -t cmake               # Clean cmake artifacts only"
    echo "  $0 -d -t build            # Remove build directory using Docker"
    echo "  $0 -d -i my/image:tag    # Clean using custom Docker image"
}

# Parse command line arguments
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
        -t|--type)
            CLEAN_TYPE="$2"
            shift 2
            ;;
        -h|--help)
            print_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            print_help
            exit 1
            ;;
    esac
done

# Validate clean type
case $CLEAN_TYPE in
    all|cmake|build)
        ;;
    *)
        echo "Error: Invalid clean type '$CLEAN_TYPE'. Must be one of: all, cmake, build"
        exit 1
        ;;
esac

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

echo -e "${BLUE}=== eNetSTL Clean Script ===${NC}"
echo -e "${BLUE}Project root: ${PROJECT_ROOT}${NC}"
echo -e "${BLUE}Clean type: ${CLEAN_TYPE}${NC}"
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

# Docker clean functionality
if [ "$USE_DOCKER" = true ]; then
    print_status "Cleaning using Docker container..."
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

    # Run Docker clean
    print_status "Starting Docker container for cleaning..."

    docker run --rm \
        -v "${PROJECT_ROOT}":/root/enetstl \
        ${LINUX_MOUNT} \
        --runtime=runc \
        -w /root/enetstl \
        ${DOCKER_IMAGE} \
        /bin/bash -c "./clean.sh -t ${CLEAN_TYPE}"

    DOCKER_EXIT_CODE=$?

    if [ $DOCKER_EXIT_CODE -eq 0 ]; then
        echo ""
        echo -e "${GREEN}=== Docker clean completed successfully! ===${NC}"
        exit 0
    else
        print_error "Docker clean failed with exit code: $DOCKER_EXIT_CODE"
        exit $DOCKER_EXIT_CODE
    fi
fi

# Local clean (non-Docker)
print_status "Performing local clean..."

case $CLEAN_TYPE in
    "all")
        print_status "Performing complete clean..."
        if [ -d "${BUILD_DIR}" ]; then
            cd "${BUILD_DIR}"
            if [ -f "Makefile" ]; then
                print_status "Running make clean_all..."
                make clean_all 2>/dev/null || true
            fi
            cd "${PROJECT_ROOT}"
        fi

        # Remove directories that might have permission issues from Docker builds
        print_status "Removing build directories..."
        sudo rm -rf build bin install bpf_skel 2>/dev/null || rm -rf build bin install bpf_skel 2>/dev/null || true

        print_status "Complete clean finished"
        ;;

    "cmake")
        print_status "Cleaning cmake artifacts..."
        if [ -d "${BUILD_DIR}" ]; then
            cd "${BUILD_DIR}"
            if [ -f "Makefile" ]; then
                print_status "Running make cmake_clean..."
                make cmake_clean
            else
                print_warning "No Makefile found in build directory"
            fi
        else
            print_warning "Build directory does not exist"
        fi
        ;;

    "build")
        print_status "Removing entire build directory..."
        if [ -d "${BUILD_DIR}" ]; then
            sudo rm -rf "${BUILD_DIR}" 2>/dev/null || rm -rf "${BUILD_DIR}" 2>/dev/null || true
            print_status "Build directory removed"
        else
            print_warning "Build directory does not exist"
        fi
        ;;
esac

echo ""
echo -e "${GREEN}=== Clean completed successfully! ===${NC}"