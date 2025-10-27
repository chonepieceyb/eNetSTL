#!/bin/bash

# This script now uses testbed_config.sh for configuration management
# Command line arguments override configuration values


source $(cd "$(dirname "$0")"; pwd)/common.sh

# Load testbed configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG_FILE="${KERNDBG_CONFIG_PATH:-$PROJECT_ROOT/configs/kernel_testbed.conf}"
if [ -f "$CONFIG_FILE" ]; then
    # Export the KERNDBG variables directly from config file
    source <(grep "^KERNDBG_" "$CONFIG_FILE")
else
    echo "[ERROR] Configuration file not found: $CONFIG_FILE"
    exit 1
fi

# Configuration variables
VM_USER=$KERNDBG_VM_USER
VM_PASSWD=$KERNDBG_VM_PASSWORD
VM_HOST="127.0.0.1"
SSH_PORT=$KERNDBG_SSH_PORT

function echo_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Copy bin files and kernel modules to VM using configuration settings."
    echo ""
    echo "OPTIONS:"
    echo "  -h, --help         Show this help message"
    echo ""
    echo "CONFIGURATION:"
    echo "  This script uses settings from kernel_testbed.conf:"
    echo "  - VM User: \$KERNDBG_VM_USER"
    echo "  - VM Password: \$KERNDBG_VM_PASSWORD"
    echo "  - SSH Port: \$KERNDBG_SSH_PORT"
    echo "  - VM Host: 127.0.0.1 (hardcoded for localhost)"
    echo ""
    echo "EXAMPLES:"
    echo "  $0                  # Copy files using configuration settings"
    echo "  $0 --help           # Show this help message"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
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

# Main function for copying files to VM
copy_files_to_vm_main() {
    echo -e "$COLOR_GREEN [INFO] Starting file copying to VM... $COLOR_OFF"

    # Test SSH connection first
    echo -e "$COLOR_YELLOW [INFO] Testing SSH connection to VM... $COLOR_OFF"
    if ! sshpass -p "$VM_PASSWD" ssh -o StrictHostKeyChecking=no -p $SSH_PORT $VM_USER@$VM_HOST "echo 'SSH connection test successful'" >/dev/null 2>&1; then
        echo -e "$COLOR_RED [ERROR] SSH connection to VM failed $COLOR_OFF"
        return 1
    fi
    echo -e "$COLOR_GREEN [INFO] SSH connection successful $COLOR_OFF"

    # Rest of the logic remains the same...
    # 1. Copy src/LKMs/*/*.ko to project_dir/linux/build
    echo -e "$COLOR_YELLOW [INFO] Copying kernel modules to linux/build... $COLOR_OFF"
    if [ ! -d ${PROJECT_ROOT}/${KERNDBG_LINUX_SRC_DIR}/build ]; then
        mkdir -p ${PROJECT_ROOT}/${KERNDBG_LINUX_SRC_DIR}/build
        echo -e "$COLOR_GREEN [INFO] Created ${PROJECT_ROOT}/${KERNDBG_LINUX_SRC_DIR}/build directory $COLOR_OFF"
    fi

    find ${PROJECT_ROOT}/src/LKMs -name "*.ko" -type f | while read ko_file; do
        cp "$ko_file" ${PROJECT_ROOT}/${KERNDBG_LINUX_SRC_DIR}/build/
        echo -e "$COLOR_GREEN [INFO] Copied $(basename "$ko_file") $COLOR_OFF"
    done

    # 2. Copy all bin to VMs /home/<user>
    echo -e "$COLOR_YELLOW [INFO] Copying bin files to VM /home/$VM_USER... $COLOR_OFF"
    if [ -d "${PROJECT_ROOT}/bin" ]; then
        # Create VM build directory
        sshpass -p "$VM_PASSWD" ssh -o StrictHostKeyChecking=no -p $SSH_PORT $VM_USER@$VM_HOST "mkdir -p ~/build" || {
            echo -e "$COLOR_RED [ERROR] Failed to create build directory on VM $COLOR_OFF"
            return 1
        }

        # Count total bin files for progress tracking
        BIN_COUNT=$(find ${PROJECT_ROOT}/bin -type f -executable | wc -l)
        echo -e "$COLOR_GREEN [INFO] Found $BIN_COUNT bin files to copy $COLOR_OFF"

        # Copy all bin files with progress
        CURRENT=0
        find ${PROJECT_ROOT}/bin -type f -executable | while read bin_file; do
            CURRENT=$((CURRENT + 1))
            filename=$(basename "$bin_file")
            echo -e "$COLOR_YELLOW [INFO] [$CURRENT/$BIN_COUNT] Copying $filename... $COLOR_OFF"

            if sshpass -p "$VM_PASSWD" scp -o StrictHostKeyChecking=no -o ConnectTimeout=10 -P $SSH_PORT "$bin_file" $VM_USER@$VM_HOST:~/; then
                echo -e "$COLOR_GREEN [INFO] [$CURRENT/$BIN_COUNT] Copied $filename to VM $COLOR_OFF"
            else
                echo -e "$COLOR_RED [ERROR] Failed to copy $filename to VM $COLOR_OFF"
                return 1
            fi
        done
    else
        echo -e "$COLOR_YELLOW [WARNING] bin directory not found, skipping bin file copy $COLOR_OFF"
    fi

    # 3. Copy all linux_dir/build/*.ko to VM /home/<user>/build
    echo -e "$COLOR_YELLOW [INFO] Copying kernel modules to VM /home/$VM_USER/build... $COLOR_OFF"
    if [ -d "${PROJECT_ROOT}/${KERNDBG_LINUX_SRC_DIR}/build" ]; then
        # Count total kernel modules for progress tracking
        KO_COUNT=$(find ${PROJECT_ROOT}/${KERNDBG_LINUX_SRC_DIR}/build -name "*.ko" -type f | wc -l)
        echo -e "$COLOR_GREEN [INFO] Found $KO_COUNT kernel modules to copy $COLOR_OFF"

        # Copy all kernel modules with progress
        CURRENT=0
        find ${PROJECT_ROOT}/${KERNDBG_LINUX_SRC_DIR}/build -name "*.ko" -type f | while read ko_file; do
            CURRENT=$((CURRENT + 1))
            filename=$(basename "$ko_file")
            echo -e "$COLOR_YELLOW [INFO] [$CURRENT/$KO_COUNT] Copying $filename... $COLOR_OFF"

            if sshpass -p "$VM_PASSWD" scp -o StrictHostKeyChecking=no -o ConnectTimeout=10 -P $SSH_PORT "$ko_file" $VM_USER@$VM_HOST:~/build/; then
                echo -e "$COLOR_GREEN [INFO] [$CURRENT/$KO_COUNT] Copied $filename to VM build directory $COLOR_OFF"
            else
                echo -e "$COLOR_RED [ERROR] Failed to copy $filename to VM build directory $COLOR_OFF"
                return 1
            fi
        done
    else
        echo -e "$COLOR_YELLOW [WARNING] ${PROJECT_ROOT}/${KERNDBG_LINUX_SRC_DIR}/build directory not found, skipping kernel module copy $COLOR_OFF"
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

    return 0
}

# Script execution logic
main_copy_files() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                echo_help
                return 0
                ;;
            *)
                echo -e "$COLOR_RED [ERROR] Unknown option: $1 $COLOR_OFF"
                echo_help
                return 1
                ;;
        esac
    done

    # Load configuration
    source "$SCRIPT_DIR/testbed_config.sh" && read_config "$CONFIG_FILE" >/dev/null 2>&1 && export_config_vars

    # Set configuration variables
    VM_USER=$KERNDBG_VM_USER
    VM_PASSWD=$KERNDBG_VM_PASSWORD
    VM_HOST="127.0.0.1"
    SSH_PORT=$KERNDBG_SSH_PORT

    # Validate configuration variables are available
    if [[ -z "$SSH_PORT" ]]; then
        echo -e "$COLOR_RED [ERROR] KERNDBG_SSH_PORT not configured in kernel_testbed.conf $COLOR_OFF"
        echo -e "$COLOR_RED [ERROR] Please set KERNDBG_SSH_PORT in your configuration $COLOR_OFF"
        return 1
    fi

    if [[ -z "$VM_USER" ]]; then
        echo -e "$COLOR_RED [ERROR] KERNDBG_VM_USER not configured in kernel_testbed.conf $COLOR_OFF"
        echo -e "$COLOR_RED [ERROR] Please set KERNDBG_VM_USER in your configuration $COLOR_OFF"
        return 1
    fi

    if [[ -z "$VM_PASSWD" ]]; then
        echo -e "$COLOR_RED [ERROR] KERNDBG_VM_PASSWORD not configured in kernel_testbed.conf $COLOR_OFF"
        echo -e "$COLOR_RED [ERROR] Please set KERNDBG_VM_PASSWORD in your configuration $COLOR_OFF"
        return 1
    fi

    # Validate port number
    if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then
        echo -e "$COLOR_RED [ERROR] Invalid SSH port: $SSH_PORT. Must be between 1-65535 $COLOR_OFF"
        echo -e "$COLOR_RED [ERROR] Please update KERNDBG_SSH_PORT in kernel_testbed.conf $COLOR_OFF"
        return 1
    fi

    # Call main function
    copy_files_to_vm_main
}

# Script execution - call main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main_copy_files "$@"
fi