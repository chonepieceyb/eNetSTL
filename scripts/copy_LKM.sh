#!/bin/bash

source $(cd "$(dirname "$0")"; pwd)"/"common.sh

set -e
if [ ! -d ${PROJECT_DIR}${LINUX}/build ]; then 
    mkdir ${PROJECT_DIR}${LINUX}/build
fi

sudo cp -rf ${PROJECT_DIR}LKM ${PROJECT_DIR}${LINUX}/build