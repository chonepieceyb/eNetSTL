#!/bin/bash
set -e

# Default Docker image
DEFAULT_IMAGE="chonepieceyb/enetstl:v0.1"
DOCKER_IMAGE="$DEFAULT_IMAGE"

# Parse command line arguments
usage() {
    echo "Usage: $0 [-i|--image DOCKER_IMAGE] [-h|--help]"
    echo "  -i, --image    Use custom Docker image (default: $DEFAULT_IMAGE)"
    echo "  -h, --help     Show this help message"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -i|--image)
            DOCKER_IMAGE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Get the project directory
PROJECT_DIR="$(dirname $(pwd))"
LINUX_DIR="${PROJECT_DIR}/linux"
VMLINUX_H_PATH="${PROJECT_DIR}/src/bpf_kern/vmlinux.h"

echo "=== eNetSTL Docker Build Environment ==="
echo "Project directory: ${PROJECT_DIR}"
echo "Docker image: ${DOCKER_IMAGE}"
echo ""

# Function to generate vmlinux.h
generate_vmlinux() {
    if [ -d "${LINUX_DIR}" ] && [ "$(ls -A ${LINUX_DIR} 2>/dev/null)" ]; then
        echo "🔄 Generating vmlinux.h from custom Linux vmlinux..."
        sudo docker run --privileged \
            --rm \
            -v "${PROJECT_DIR}":/root/enetstl \
            -v "${LINUX_DIR}":/root/enetstl/linux \
            "${DOCKER_IMAGE}" /bin/sh \
            -c '/usr/local/sbin/bpftool btf dump file /root/enetstl/linux/vmlinux format c > /root/enetstl/src/bpf_kern/vmlinux.h'
    else
        echo "🔄 Generating vmlinux.h from system BTF..."
        sudo docker run --privileged \
            --rm \
            -v "${PROJECT_DIR}":/root/enetstl \
            -v /sys/kernel/btf:/sys/kernel/btf "${DOCKER_IMAGE}" /bin/sh \
            -c '/usr/local/sbin/bpftool btf dump file /sys/kernel/btf/vmlinux format c > /root/enetstl/src/bpf_kern/vmlinux.h'
    fi
    echo "✅ vmlinux.h generated successfully!"
    echo ""
}

# Check if vmlinux.h exists, if not generate it
if [ ! -f "${VMLINUX_H_PATH}" ]; then
    echo "⚠️  vmlinux.h not found at ${VMLINUX_H_PATH}"
    generate_vmlinux
else
    echo "✅ Found existing vmlinux.h at ${VMLINUX_H_PATH}"
    echo ""
fi

# Check for custom Linux directory
if [ -d "${LINUX_DIR}" ] && [ "$(ls -A ${LINUX_DIR} 2>/dev/null)" ]; then
    echo "🐧 Custom Linux directory detected at ${LINUX_DIR}"
    echo "   Using custom Linux source for BPF compilation"
    echo ""

    # Check if it's a symlink and provide info
    if [ -L "${LINUX_DIR}" ]; then
        REAL_LINUX_DIR="$(readlink -f ${LINUX_DIR})"
        echo "📎 Linux directory is a symlink pointing to: ${REAL_LINUX_DIR}"
        echo ""
    fi

    # Mount custom linux directory in Docker
    LINUX_MOUNT="-v ${LINUX_DIR}:/root/enetstl/linux"
    CUSTOM_LINUX_MSG="🐧 Using custom Linux source"
else
    echo "🔧 No custom Linux directory found at ${LINUX_DIR}"
    echo "   Using system libbpf and headers"
    echo ""
    LINUX_MOUNT=""
    CUSTOM_LINUX_MSG="🔧 Using system libbpf"
fi

# Build and run the main Docker container
echo "🚀 Starting eNetSTL build container..."
echo "${CUSTOM_LINUX_MSG}"
echo ""

sudo docker run  \
    -it \
    --hostname=enetstl-build \
    -v "${PROJECT_DIR}":/root/enetstl \
    -v /sys/fs/bpf:/sys/fs/bpf \
    -v /lib/modules/$(uname -r)/build:/lib/modules/$(uname -r)/build \
    ${LINUX_MOUNT} \
    --network=host \
    --privileged \
    --runtime=runc \
    -w /root/enetstl \
    "${DOCKER_IMAGE}"

echo ""
echo "👋 eNetSTL Docker session ended"