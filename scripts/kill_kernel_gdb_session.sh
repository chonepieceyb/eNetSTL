#!/bin/bash
#TODO: enchance echo how to attach the tmux session 
source $(cd "$(dirname "$0")"; pwd)"/"common.sh""

if [ $# -eq 0 ]; then
    echo "Usage: $0 <session_pattern>"
    echo "Example: $0 kernel-testbed-yb"
    echo "Example: $0 kernel-testbed-yb-20231201"
    exit 1
fi

pattern="$1"
echo -e "$COLOR_YELLOW [INFO] Looking for sessions matching pattern: $pattern $COLOR_OFF"

# Find and kill sessions matching the pattern
sessions_found=0
sudo tmux list-sessions 2>/dev/null | grep "$pattern" | while read -r session; do
    session_to_kill=$(echo "$session" | cut -d: -f1)
    echo -e "$COLOR_YELLOW [INFO] Killing session: $session_to_kill $COLOR_OFF"
    sudo tmux kill-session -t "$session_to_kill" > /dev/null 2>&1
    sessions_found=$((sessions_found + 1))
done

if [ $sessions_found -eq 0 ]; then
    echo -e "$COLOR_YELLOW [INFO] No sessions found matching pattern: $pattern $COLOR_OFF"
    echo -e "$COLOR_CYAN [INFO] To list all active tmux sessions, run: sudo tmux list-sessions $COLOR_OFF"
    echo -e "$COLOR_CYAN [INFO] To attach to a tmux session, run: sudo tmux attach -t <session_name> $COLOR_OFF"
    echo -e "$COLOR_CYAN [INFO] To create a new kernel debug session, run: ./scripts/new_kernel_dbg_session.sh $COLOR_OFF"
else
    echo -e "$COLOR_GREEN [INFO] Killed $sessions_found session(s) matching pattern: $pattern $COLOR_OFF"
fi