#!/bin/bash

echo "check https://www.kernel.org/doc/html/latest/admin-guide/dynamic-debug-howto.html for details"
set -e

cmd="su - root -c 'echo \"module $1 +p \" > /proc/dynamic_debug/control'"
eval $cmd 