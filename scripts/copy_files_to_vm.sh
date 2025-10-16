#!/bin/bash

source $(cd "$(dirname "$0")"; pwd)"/"common.sh

# Configuration variables
VM_USER=${VM_USER:-"seu"}
VM_PASSWD=${VM_PASSWD:-"123456"}
VM_HOST=${VM_HOST:-"127.0.0.1"}

function echo_help() {
    echo "Usage: $0 -p <ssh_port> [-u <user>] [-h <host>] [-P <password>]"
    echo ""
    echo "Copy bin files and kernel modules to VM using specified SSH port."
    echo ""
    echo "OPTIONS:"
    echo "  -p, --port         SSH port number (required)"
    echo "  -u, --user         VM username (default: seu)"
    echo "  -h, --host         VM host address (default: 127.0.0.1)"
    echo "  -P, --password     VM password (default: 123456)"
    echo "  --help             Show this help message"
    echo ""
    echo "EXAMPLES:"
    echo "  $0 -p 3333                     # Use port 3333 with default settings"
    echo "  $0 -p 3334 -u myuser -h 192.168.1.100  # Custom user and host"
}

function validate_port() {
    local port=$1
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        echo -e "$COLOR_RED [ERROR] Invalid port: $port. Must be between 1-65535 $COLOR_OFF"
        exit 1
    fi
}

# Parse command line arguments
SSH_PORT=""
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--port)
            SSH_PORT="$2"
            shift 2
            ;;
        -u|--user)
            VM_USER="$2"
            shift 2
            ;;
        -h|--host)
            VM_HOST="$2"
            shift 2
            ;;
        -P|--password)
            VM_PASSWD="$2"
            shift 2
            ;;
        --help)
            echo_help
            exit 0
            ;;
        *)
            echo -e "$COLOR_RED [ERROR] Unknown option: $1 $COLOR_OFF"
            echo_help
            exit 1
            ;;
    esac
done

# Validate required arguments
if [ -z "$SSH_PORT" ]; then
    echo -e "$COLOR_RED [ERROR] SSH port is required $COLOR_OFF"
    echo_help
    exit 1
fi

validate_port "$SSH_PORT"

set -e

echo -e "$COLOR_GREEN [INFO] Starting file copying to VM... $COLOR_OFF"
echo -e "$COLOR_GREEN [INFO] VM: $VM_USER@$VM_HOST:$SSH_PORT $COLOR_OFF"

# Test SSH connection first
echo -e "$COLOR_YELLOW [INFO] Testing SSH connection to VM... $COLOR_OFF"
if ! sshpass -p "$VM_PASSWD" ssh -o StrictHostKeyChecking=no -p $SSH_PORT $VM_USER@$VM_HOST "echo 'SSH connection test successful'" >/dev/null 2>&1; then
    echo -e "$COLOR_RED [ERROR] SSH connection to VM failed $COLOR_OFF"
    exit 1
fi
echo -e "$COLOR_GREEN [INFO] SSH connection successful $COLOR_OFF"

# 1. Copy src/LKMs/*/*.ko to project_dir/linux/build
echo -e "$COLOR_YELLOW [INFO] Copying kernel modules to linux/build... $COLOR_OFF"
if [ ! -d ${PROJECT_DIR}${LINUX}/build ]; then
    mkdir -p ${PROJECT_DIR}${LINUX}/build
    echo -e "$COLOR_GREEN [INFO] Created ${PROJECT_DIR}${LINUX}/build directory $COLOR_OFF"
fi

find ${PROJECT_DIR}src/LKMs -name "*.ko" -type f | while read ko_file; do
    cp "$ko_file" ${PROJECT_DIR}${LINUX}/build/
    echo -e "$COLOR_GREEN [INFO] Copied $(basename "$ko_file") $COLOR_OFF"
done

# 2. Copy all bin to VMs /home/<user>
echo -e "$COLOR_YELLOW [INFO] Copying bin files to VM /home/$VM_USER... $COLOR_OFF"
if [ -d "${PROJECT_DIR}bin" ]; then
    # Create VM build directory
    sshpass -p "$VM_PASSWD" ssh -o StrictHostKeyChecking=no -p $SSH_PORT $VM_USER@$VM_HOST "mkdir -p ~/build" || {
        echo -e "$COLOR_RED [ERROR] Failed to create build directory on VM $COLOR_OFF"
        exit 1
    }

    # Count total bin files for progress tracking
    BIN_COUNT=$(find ${PROJECT_DIR}bin -type f -executable | wc -l)
    echo -e "$COLOR_GREEN [INFO] Found $BIN_COUNT bin files to copy $COLOR_OFF"

    # Copy all bin files with progress
    CURRENT=0
    find ${PROJECT_DIR}bin -type f -executable | while read bin_file; do
        CURRENT=$((CURRENT + 1))
        filename=$(basename "$bin_file")
        echo -e "$COLOR_YELLOW [INFO] [$CURRENT/$BIN_COUNT] Copying $filename... $COLOR_OFF"

        if sshpass -p "$VM_PASSWD" scp -o StrictHostKeyChecking=no -o ConnectTimeout=10 -P $SSH_PORT "$bin_file" $VM_USER@$VM_HOST:~/; then
            echo -e "$COLOR_GREEN [INFO] [$CURRENT/$BIN_COUNT] Copied $filename to VM $COLOR_OFF"
        else
            echo -e "$COLOR_RED [ERROR] Failed to copy $filename to VM $COLOR_OFF"
            exit 1
        fi
    done
else
    echo -e "$COLOR_YELLOW [WARNING] bin directory not found, skipping bin file copy $COLOR_OFF"
fi

# 3. Copy all linux_dir/build/*.ko to VM /home/<user>/build
echo -e "$COLOR_YELLOW [INFO] Copying kernel modules to VM /home/$VM_USER/build... $COLOR_OFF"
if [ -d "${PROJECT_DIR}${LINUX}/build" ]; then
    # Count total kernel modules for progress tracking
    KO_COUNT=$(find ${PROJECT_DIR}${LINUX}/build -name "*.ko" -type f | wc -l)
    echo -e "$COLOR_GREEN [INFO] Found $KO_COUNT kernel modules to copy $COLOR_OFF"

    # Copy all kernel modules with progress
    CURRENT=0
    find ${PROJECT_DIR}${LINUX}/build -name "*.ko" -type f | while read ko_file; do
        CURRENT=$((CURRENT + 1))
        filename=$(basename "$ko_file")
        echo -e "$COLOR_YELLOW [INFO] [$CURRENT/$KO_COUNT] Copying $filename... $COLOR_OFF"

        if sshpass -p "$VM_PASSWD" scp -o StrictHostKeyChecking=no -o ConnectTimeout=10 -P $SSH_PORT "$ko_file" $VM_USER@$VM_HOST:~/build/; then
            echo -e "$COLOR_GREEN [INFO] [$CURRENT/$KO_COUNT] Copied $filename to VM build directory $COLOR_OFF"
        else
            echo -e "$COLOR_RED [ERROR] Failed to copy $filename to VM build directory $COLOR_OFF"
            exit 1
        fi
    done
else
    echo -e "$COLOR_YELLOW [WARNING] ${PROJECT_DIR}${LINUX}/build directory not found, skipping kernel module copy $COLOR_OFF"
fi

# 4. Verify all operations succeeded
echo -e "$COLOR_YELLOW [INFO] Verifying all operations... $COLOR_OFF"

# Verify files exist on VM
bin_count=$(sshpass -p "$VM_PASSWD" ssh -o StrictHostKeyChecking=no -p $SSH_PORT $VM_USER@$VM_HOST "find ~ -maxdepth 1 -type f -executable -name '*_user' | wc -l" || echo "0")
ko_count=$(sshpass -p "$VM_PASSWD" ssh -o StrictHostKeyChecking=no -p $SSH_PORT $VM_USER@$VM_HOST "ls -1 ~/build/*.ko 2>/dev/null | wc -l" || echo "0")

echo -e "$COLOR_GREEN [INFO] Verification results: $COLOR_OFF"
echo -e "$COLOR_GREEN [INFO] - SSH connection: SUCCESSFUL $COLOR_OFF"
echo -e "$COLOR_GREEN [INFO] - Bin files on VM: $bin_count files $COLOR_OFF"
echo -e "$COLOR_GREEN [INFO] - Kernel modules on VM: $ko_count files $COLOR_OFF"

echo -e "$COLOR_GREEN [SUCCESS] All file copy operations completed successfully! $COLOR_OFF"
echo -e "$COLOR_GREEN [INFO] You can connect to the VM with: ssh -p $SSH_PORT $VM_USER@$VM_HOST $COLOR_OFF"