#!/bin/bash

# Kill Kernel Debug Session Script for eNetSTL
# This script kills kernel debugging tmux sessions based on configuration or pattern

source $(cd "$(dirname "$0")"; pwd)/common.sh

# Load testbed configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Load testbed configuration
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG_FILE="${KERNDBG_CONFIG_PATH:-$PROJECT_ROOT/configs/kernel_testbed.conf}"

# Default session pattern from configuration - will be set after loading config
DEFAULT_PATTERN=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
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

# Function to show help
show_help() {
    printf "Usage: %s [OPTIONS] [PATTERN]\n" "$0"
    printf "\n"
    printf "Kill kernel debugging tmux sessions.\n"
    printf "\n"
    printf "ARGUMENTS:\n"
    echo '  PATTERN               Session name pattern to match (optional)'
    echo "                       If not provided, uses config default: $DEFAULT_PATTERN"
    printf "\n"
    printf "OPTIONS:\n"
    echo '  -a, --all            Kill all kernel debug sessions'
    echo '  -l, --list           List sessions without killing them'
    echo '  -f, --force          Force kill without confirmation'
    echo '  -h, --help           Show this help message'
    printf "\n"
    printf "EXAMPLES:\n"
    echo '  $0                           # Kill sessions with default pattern'
    echo '  $0 my-session                # Kill sessions matching my-session'
    echo '  $0 --all                     # Kill all kernel debug sessions'
    echo '  $0 --list                    # List all sessions'
    echo '  $0 --force kernel_dbg        # Force kill matching sessions'
    printf "\n"
    printf "CONFIGURATION:\n"
    echo "  Session prefix is loaded from testbed_config.sh"
    echo "  Default pattern: $DEFAULT_PATTERN"
}

# Function to list sessions
list_sessions() {
    local pattern="$1"

    print_info "Listing sessions matching pattern: $pattern"

    local sessions_found=0
    sudo tmux list-sessions 2>/dev/null | grep "$pattern" | while read -r session; do
        session_name=$(echo "$session" | cut -d: -f1)
        echo -e "  ${CYAN}Session:${NC} $session_name"
        sessions_found=$((sessions_found + 1))
    done

    if [ $sessions_found -eq 0 ]; then
        print_warning "No sessions found matching pattern: $pattern"
    else
        printf "${BLUE}[INFO]${NC} Found %d sessions matching pattern: %s\n" "$sessions_found" "$pattern"
    fi
}

# Function to kill sessions with optional confirmation
kill_sessions() {
    local pattern="$1"
    local force_confirm="$2"

    print_info "Looking for sessions matching pattern: $pattern"

    # First, list the sessions that would be killed
    local sessions_to_kill=()
    sudo tmux list-sessions 2>/dev/null | grep "$pattern" | while read -r session; do
        session_name=$(echo "$session" | cut -d: -f1)
        sessions_to_kill+=("$session_name")
    done

    # Re-run to get the count since we can't easily pass arrays between processes
    local sessions_count
    sessions_count=$(sudo tmux list-sessions 2>/dev/null | grep "$pattern" | wc -l)

    if [ "$sessions_count" -eq 0 ]; then
        print_warning "No sessions found matching pattern: $pattern"
        print_info "To list all active tmux sessions, run: sudo tmux list-sessions"
        return 0
    fi

    # Show sessions that will be killed
    print_info "Sessions that will be killed:"
    sudo tmux list-sessions 2>/dev/null | grep "$pattern" | while read -r session; do
        session_name=$(echo "$session" | cut -d: -f1)
        echo -e "  ${YELLOW}- $session_name${NC}"
    done

    # Ask for confirmation unless force is enabled
    if [ "$force_confirm" != "true" ]; then
        echo
        printf "Do you want to kill these %d sessions? [y/N]: " "$sessions_count"; read -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Operation cancelled"
            return 0
        fi
    fi

    # Kill the sessions
    local killed_count=0
    sudo tmux list-sessions 2>/dev/null | grep "$pattern" | while read -r session; do
        session_name=$(echo "$session" | cut -d: -f1)
        print_info "Killing session: $session_name"

        if sudo tmux kill-session -t "$session_name" > /dev/null 2>&1; then
            echo -e "  ${GREEN}✓ Killed${NC}"
            killed_count=$((killed_count + 1))
        else
            echo -e "  ${RED}✗ Failed to kill${NC}"
        fi
    done

    print_success "Operation completed"
}

# Parse command line arguments
PATTERN="$DEFAULT_PATTERN"
KILL_ALL=false
LIST_ONLY=false
FORCE_KILL=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -a|--all)
            KILL_ALL=true
            PATTERN=".*"  # Match all sessions
            shift
            ;;
        -l|--list)
            LIST_ONLY=true
            shift
            ;;
        -f|--force)
            FORCE_KILL=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        -*)
            print_error "Unknown option: $1"
            show_help
            exit 1
            ;;
        *)
            PATTERN="$1"
            shift
            ;;
    esac
done

# Main function for killing kernel debug sessions (can be called by other scripts)
kill_kernel_debug_sessions() {
    local pattern="$1"
    local force_kill="$2"
    local list_only="$3"

    # Use defaults if not provided
    pattern="${pattern:-$DEFAULT_PATTERN}"
    force_kill="${force_kill:-false}"
    list_only="${list_only:-false}"

    # Call the appropriate function
    if [ "$list_only" = true ]; then
        list_sessions "$pattern"
    else
        kill_sessions "$pattern" "$force_kill"
    fi
}

# Script execution - call main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Parse command line arguments (existing logic)
    while [[ $# -gt 0 ]]; do
        case $1 in
            -a|--all)
                KILL_ALL=true
                PATTERN=".*"  # Match all sessions
                shift
                ;;
            -l|--list)
                LIST_ONLY=true
                shift
                ;;
            -f|--force)
                FORCE_KILL=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -*)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
            *)
                PATTERN="$1"
                shift
                ;;
        esac
    done

    # Set default pattern if still empty
    if [ -z "$PATTERN" ]; then
        PATTERN="$DEFAULT_PATTERN"
    fi

    # Load configuration and display info
    source "$SCRIPT_DIR/testbed_config.sh" && read_config "$CONFIG_FILE" >/dev/null 2>&1 && export_config_vars

    # Set default pattern after configuration is loaded
    if [ -z "$DEFAULT_PATTERN" ]; then
        DEFAULT_PATTERN="$KERNDBG_TMUX_SESSION_PREFIX"
    fi

    print_info "=== Kernel Debug Session Killer ==="
    print_info "Session Pattern: $PATTERN"

    # Call the main function
    kill_kernel_debug_sessions "$PATTERN" "$FORCE_KILL" "$LIST_ONLY"
fi
