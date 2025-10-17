#!/bin/bash
set -e

# Default values
USE_DOCKER=false
DOCKER_IMAGE="chonepieceyb/enetstl:v0.1"
EXECUTABLE=""
EXECUTABLE_ARGS=()

# Function to print help
print_help() {
    echo "Usage: $0 [OPTIONS] <executable> [executable_args...]"
    echo ""
    echo "Options:"
    echo "  -d, --docker              Run using Docker container"
    echo "  -i, --image IMAGE         Specify Docker image (default: $DOCKER_IMAGE)"
    echo "  -h, --help                 Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 my_program              # Run locally"
    echo "  $0 my_program arg1 arg2    # Run locally with arguments"
    echo "  $0 -d my_program           # Run using Docker"
    echo "  $0 -d -i my/image:tag my_program  # Run using custom Docker image"
    echo ""
    echo "Available executables:"
    if [ -d "bin" ]; then
        ls -la bin/ 2>/dev/null | grep -E "^\-.*x.*" | awk '{print "  " $9}'
    else
        echo "  (bin directory not found - run ./build.sh first)"
    fi
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
        -h|--help)
            print_help
            exit 0
            ;;
        *)
            if [ -z "$EXECUTABLE" ]; then
                EXECUTABLE="$1"
            else
                EXECUTABLE_ARGS+=("$1")
            fi
            shift
            ;;
    esac
done

# Check if executable was specified
if [ -z "$EXECUTABLE" ]; then
    echo -e "\033[0;31m[ERROR]\033[0m No executable specified!"
    echo ""
    print_help
    exit 1
fi

# Get the script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}"
BIN_DIR="${PROJECT_ROOT}/bin"
EXECUTABLE_PATH="${BIN_DIR}/${EXECUTABLE}"

# Color output for better UX
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== eNetSTL Run Script ===${NC}"
echo -e "${BLUE}Project root: ${PROJECT_ROOT}${NC}"
echo -e "${BLUE}Executable: ${EXECUTABLE}${NC}"
if [ ${#EXECUTABLE_ARGS[@]} -gt 0 ]; then
    echo -e "${BLUE}Arguments: ${EXECUTABLE_ARGS[*]}${NC}"
fi
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

# Docker run functionality
if [ "$USE_DOCKER" = true ]; then
    print_status "Running using Docker container..."
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

    # Prepare executable arguments string
    EXEC_ARGS_STR=""
    for arg in "${EXECUTABLE_ARGS[@]}"; do
        EXEC_ARGS_STR="${EXEC_ARGS_STR} ${arg}"
    done

    print_status "Executable arguments: ${EXEC_ARGS_STR}"

    # Run Docker container
    print_status "Starting Docker container to run executable..."

    docker run --rm \
        -v "${PROJECT_ROOT}":/root/enetstl \
        -v /sys/fs/bpf:/sys/fs/bpf \
        ${LINUX_MOUNT} \
        --runtime=runc \
        -w /root/enetstl \
        --privileged \
        ${DOCKER_IMAGE} \
        /bin/bash -c "cd /root/enetstl && ./run_bin.sh ${EXECUTABLE}${EXEC_ARGS_STR}"

    DOCKER_EXIT_CODE=$?

    if [ $DOCKER_EXIT_CODE -eq 0 ]; then
        echo ""
        echo -e "${GREEN}=== Docker execution completed successfully! ===${NC}"
        exit 0
    else
        print_error "Docker execution failed with exit code: $DOCKER_EXIT_CODE"
        exit $DOCKER_EXIT_CODE
    fi
fi

# Local execution (non-Docker)
# Check if executable exists
if [ ! -f "$EXECUTABLE_PATH" ]; then
    print_error "Executable not found: $EXECUTABLE_PATH"
    print_error "Please run ./build.sh first to build the executables."
    exit 1
fi

# Check if executable is executable
if [ ! -x "$EXECUTABLE_PATH" ]; then
    print_error "File is not executable: $EXECUTABLE_PATH"
    print_error "Please check file permissions."
    exit 1
fi

print_status "Running executable: $EXECUTABLE_PATH"

# Change to project root directory (important for relative paths)
cd "${PROJECT_ROOT}"

# Run the executable with arguments
if [ ${#EXECUTABLE_ARGS[@]} -gt 0 ]; then
    print_status "With arguments: ${EXECUTABLE_ARGS[*]}"
    "${EXECUTABLE_PATH}" "${EXECUTABLE_ARGS[@]}"
else
    "${EXECUTABLE_PATH}"
fi

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo ""
    echo -e "${GREEN}=== Execution completed successfully! ===${NC}"
else
    print_error "Execution failed with exit code: $EXIT_CODE"
    exit $EXIT_CODE
fi