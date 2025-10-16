#!/bin/bash

source $(cd "$(dirname "$0")"; pwd)"/"common.sh

# Configuration
CMAKE_DIR="${PROJECT_DIR}cmake"
BPF_BLACKLIST="${CMAKE_DIR}/bpf_blacklist.txt"
C_BLACKLIST="${CMAKE_DIR}/c_blacklist.txt"
BPF_WHITELIST="${CMAKE_DIR}/bpf_whitelist.txt"
C_WHITELIST="${CMAKE_DIR}/c_whitelist.txt"

# Available experiments
AVAILABLE_EXPS=(
    "exp1-2"
    "exp1-arena"
    "exp1-static-ptr"
    "exp3"
    "exp4"
    "exp5"
    "exp6"
    "exp7"
    "exp8"
    "exp9"
    "exp-control-plane"
    "utils"
)

function echo_help() {
    echo "Usage: $0 [OPTIONS] <experiment1> [experiment2] [experiment3] ..."
    echo ""
    echo "Manage whitelist and blacklist for selective compilation of experiments."
    echo ""
    echo "OPTIONS:"
    echo "  -w, --whitelist    Add experiment(s) to whitelist (exclusive compilation)"
    echo "  -b, --blacklist    Add experiment(s) to blacklist (exclude from compilation)"
    echo "  -c, --clear        Clear all whitelist and blacklist files"
    echo "  -l, --list         List current whitelist and blacklist contents"
    echo "  -h, --help         Show this help message"
    echo ""
    echo "EXAMPLES:"
    echo "  $0 -w exp1-static-ptr                    # Whitelist single experiment"
    echo "  $0 -w exp1-2 exp3 exp4                   # Whitelist multiple experiments"
    echo "  $0 -b exp1-arena                         # Blacklist single experiment"
    echo "  $0 -b exp1-arena exp5                    # Blacklist multiple experiments"
    echo "  $0 -c                                    # Clear all lists"
    echo "  $0 -l                                    # List current contents"
    echo ""
    echo "AVAILABLE EXPERIMENTS:"
    printf "  %s\n" "${AVAILABLE_EXPS[@]}"
}

function validate_experiment() {
    local exp=$1
    for available_exp in "${AVAILABLE_EXPS[@]}"; do
        if [[ "$exp" == "$available_exp" ]]; then
            return 0
        fi
    done
    echo -e "$COLOR_RED [ERROR] Invalid experiment: $exp $COLOR_OFF"
    echo -e "$COLOR_RED [ERROR] Available experiments: ${AVAILABLE_EXPS[*]} $COLOR_OFF"
    return 1
}

function ensure_cmake_dir() {
    if [ ! -d "$CMAKE_DIR" ]; then
        mkdir -p "$CMAKE_DIR"
        echo -e "$COLOR_GREEN [INFO] Created cmake directory $COLOR_OFF"
    fi
}

function clear_all_lists() {
    echo -e "$COLOR_YELLOW [INFO] Clearing all whitelist and blacklist files... $COLOR_OFF"

    ensure_cmake_dir

    > "$BPF_BLACKLIST"
    > "$C_BLACKLIST"
    > "$BPF_WHITELIST"
    > "$C_WHITELIST"

    echo -e "$COLOR_GREEN [SUCCESS] All whitelist and blacklist files cleared $COLOR_OFF"
}

function add_to_whitelist() {
    local experiments=("$@")
    echo -e "$COLOR_YELLOW [INFO] Adding ${#experiments[@]} experiment(s) to whitelist... $COLOR_OFF"

    ensure_cmake_dir

    # Clear existing content and add experiments
    > "$BPF_WHITELIST"
    > "$C_WHITELIST"

    for exp in "${experiments[@]}"; do
        echo "$exp" >> "$BPF_WHITELIST"
        echo "$exp" >> "$C_WHITELIST"
        echo -e "$COLOR_GREEN [SUCCESS] Whitelisted $exp $COLOR_OFF"
    done

    # Clear blacklists when using whitelist
    > "$BPF_BLACKLIST"
    > "$C_BLACKLIST"

    echo -e "$COLOR_INFO [INFO] Blacklists cleared due to exclusive whitelist mode $COLOR_OFF"
}

function add_to_blacklist() {
    local experiments=("$@")
    echo -e "$COLOR_YELLOW [INFO] Adding ${#experiments[@]} experiment(s) to blacklist... $COLOR_OFF"

    ensure_cmake_dir

    local added_count=0
    local skipped_count=0

    for exp in "${experiments[@]}"; do
        # Check if already blacklisted
        if grep -q "^$exp$" "$BPF_BLACKLIST" 2>/dev/null; then
            echo -e "$COLOR_YELLOW [WARNING] $exp is already blacklisted $COLOR_OFF"
            ((skipped_count++))
        else
            # Add to blacklists
            echo "$exp" >> "$BPF_BLACKLIST"
            echo "$exp" >> "$C_BLACKLIST"
            echo -e "$COLOR_GREEN [SUCCESS] Blacklisted $exp $COLOR_OFF"
            ((added_count++))
        fi
    done

    # Clear whitelists when using blacklist
    > "$BPF_WHITELIST"
    > "$C_WHITELIST"

    echo -e "$COLOR_INFO [INFO] $added_count experiments blacklisted, $skipped_count skipped $COLOR_OFF"
    echo -e "$COLOR_INFO [INFO] Whitelists cleared due to blacklist mode $COLOR_OFF"
}

function list_lists() {
    echo -e "$COLOR_GREEN [INFO] Current whitelist and blacklist contents: $COLOR_OFF"
    echo ""

    # Check BPF whitelist
    if [ -f "$BPF_WHITELIST" ] && [ -s "$BPF_WHITELIST" ]; then
        echo -e "$COLOR_YELLOW BPF Whitelist: $COLOR_OFF"
        cat "$BPF_WHITELIST" | while read line; do
            echo "  - $line"
        done
    else
        echo -e "$COLOR_YELLOW BPF Whitelist: (empty) $COLOR_OFF"
    fi

    # Check C whitelist
    if [ -f "$C_WHITELIST" ] && [ -s "$C_WHITELIST" ]; then
        echo -e "$COLOR_YELLOW C Whitelist: $COLOR_OFF"
        cat "$C_WHITELIST" | while read line; do
            echo "  - $line"
        done
    else
        echo -e "$COLOR_YELLOW C Whitelist: (empty) $COLOR_OFF"
    fi

    # Check BPF blacklist
    if [ -f "$BPF_BLACKLIST" ] && [ -s "$BPF_BLACKLIST" ]; then
        echo -e "$COLOR_RED BPF Blacklist: $COLOR_OFF"
        cat "$BPF_BLACKLIST" | while read line; do
            echo "  - $line"
        done
    else
        echo -e "$COLOR_RED BPF Blacklist: (empty) $COLOR_OFF"
    fi

    # Check C blacklist
    if [ -f "$C_BLACKLIST" ] && [ -s "$C_BLACKLIST" ]; then
        echo -e "$COLOR_RED C Blacklist: $COLOR_OFF"
        cat "$C_BLACKLIST" | while read line; do
            echo "  - $line"
        done
    else
        echo -e "$COLOR_RED C Blacklist: (empty) $COLOR_OFF"
    fi

    echo ""
}

# Parse command line arguments
MODE=""
EXPERIMENTS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        -w|--whitelist)
            MODE="whitelist"
            shift
            ;;
        -b|--blacklist)
            MODE="blacklist"
            shift
            ;;
        -c|--clear)
            MODE="clear"
            shift
            ;;
        -l|--list)
            MODE="list"
            shift
            ;;
        -h|--help)
            echo_help
            exit 0
            ;;
        -*)
            echo -e "$COLOR_RED [ERROR] Unknown option: $1 $COLOR_OFF"
            echo_help
            exit 1
            ;;
        *)
            EXPERIMENTS+=("$1")
            shift
            ;;
    esac
done

# Main execution logic
case "$MODE" in
    "whitelist")
        if [ ${#EXPERIMENTS[@]} -eq 0 ]; then
            echo -e "$COLOR_RED [ERROR] At least one experiment name required for whitelist mode $COLOR_OFF"
            echo_help
            exit 1
        fi

        # Validate all experiments
        for exp in "${EXPERIMENTS[@]}"; do
            validate_experiment "$exp" || exit 1
        done

        add_to_whitelist "${EXPERIMENTS[@]}"
        ;;
    "blacklist")
        if [ ${#EXPERIMENTS[@]} -eq 0 ]; then
            echo -e "$COLOR_RED [ERROR] At least one experiment name required for blacklist mode $COLOR_OFF"
            echo_help
            exit 1
        fi

        # Validate all experiments
        for exp in "${EXPERIMENTS[@]}"; do
            validate_experiment "$exp" || exit 1
        done

        add_to_blacklist "${EXPERIMENTS[@]}"
        ;;
    "clear")
        clear_all_lists
        ;;
    "list")
        list_lists
        ;;
    "")
        echo -e "$COLOR_RED [ERROR] No mode specified $COLOR_OFF"
        echo_help
        exit 1
        ;;
    *)
        echo -e "$COLOR_RED [ERROR] Invalid mode: $MODE $COLOR_OFF"
        echo_help
        exit 1
        ;;
esac

# Show final status if not listing
if [ "$MODE" != "list" ]; then
    echo ""
    echo -e "$COLOR_GREEN [INFO] Final status: $COLOR_OFF"
    list_lists
fi