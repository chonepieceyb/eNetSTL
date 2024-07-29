#!/bin/bash

session_name="kernel-testbed-yhl"
sudo tmux kill-session -t $session_name > /dev/null 2>&1